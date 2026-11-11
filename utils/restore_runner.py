#!/usr/bin/python3
# coding=utf-8

#   Copyright 2026 EPAM Systems
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

""" Project restore applied in a worker process

The web process validates the request, spools the upload to disk and starts
restore_worker.py in a fresh interpreter, which reads the spool and applies
it. Under gevent the web process is one OS thread, so parsing and decrypting a
large backup there stalls every other request: in the worker it costs that
process only. A fork of the web process is not used: it inherits the gevent
hub and listener threads and was seen to stall mid-restore.

The worker never calls RPC: everything it needs is resolved by the web process
and handed over on its stdin.
"""

import codecs
import json
import os
import subprocess
import sys
import tempfile
import time

from pylon.core.tools import log  # pylint: disable=E0611,E0401

from . import backup_crypto
from . import chat_backup
from . import restore_jobs
from . import restore_storage
from .chat_restore import AttachmentRestorer, iter_zip_sql, open_backup_zip
from .skill_files_backup import SkillFileRestorer, restore_summary_counts
from .project_restore import (
    KIND_SAFE, HEADER_SCAN_BYTES, SAFE_RESTORE_DENIED_TABLES,
    detect_artifact_kind, restore_safe_backup, run_psql, server_settings,
)


READ_CHUNK = 262144
HEARTBEAT_SECONDS = 30

WORKER_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "restore_worker.py")


class RestoreFailed(Exception):
    """ A restore error with the response a synchronous restore gave """

    def __init__(self, body, status_code):
        super().__init__(body.get("error"))
        self.body = body
        self.status_code = status_code


def spool_dir(config):
    path = (config or {}).get("restore_spool_dir") or os.path.join(tempfile.gettempdir(), "project_restore")
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


def spool_upload(stream, directory):
    """ Upload copied to a named file the child can reopen, (path, size) """
    handle = tempfile.NamedTemporaryFile(  # pylint: disable=R1732
        dir=directory, prefix="restore_", suffix=".bin", delete=False,
    )
    size = 0
    try:
        with handle:
            while True:
                chunk = stream.read(READ_CHUNK)
                if not chunk:
                    break
                handle.write(chunk)
                size += len(chunk)
    except Exception:
        remove_spool(handle.name)
        raise
    return handle.name, size


def remove_spool(path):
    try:
        os.unlink(path)
    except OSError:
        pass


def remove_stale_spools(directory, max_age_seconds):
    """ Spool files left by a process that died before cleaning up """
    removed = 0
    cutoff = time.time() - max_age_seconds
    try:
        names = os.listdir(directory)
    except OSError:
        return 0
    for name in names:
        path = os.path.join(directory, name)
        try:
            if name.startswith("restore_") and os.path.getmtime(path) < cutoff:
                os.unlink(path)
                removed += 1
        except OSError:
            continue
    return removed


def _byte_chunks(path):
    def opener():
        with open(path, "rb") as source:
            while True:
                chunk = source.read(READ_CHUNK)
                if not chunk:
                    break
                yield chunk
    return opener


def _text_chunks(open_bytes):
    def opener():
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        for chunk in open_bytes():
            text = decoder.decode(chunk)
            if text:
                yield text
        tail = decoder.decode(b"", True)
        if tail:
            yield tail
    return opener


def _read_head(open_bytes, limit):
    head = bytearray()
    for chunk in open_bytes():
        head += chunk
        if len(head) >= limit:
            break
    return bytes(head[:limit])


def _native(module_name, name):
    """ The unpatched stdlib callable: a greenlet would not run while the restore holds the CPU """
    try:
        from gevent import monkey  # pylint: disable=E0401,C0415
        return monkey.get_original(module_name, name)
    except Exception:  # pylint: disable=W0703
        return getattr(__import__(module_name), name)


class Heartbeat:
    """ Liveness ping of the job row from an OS thread of its own

    It runs through every phase of the restore, also those that read no input
    (attachment uploads, merges, the psql commit).
    """

    def __init__(self, store, job_id, interval=HEARTBEAT_SECONDS):
        self.store = store
        self.job_id = job_id
        self.interval = interval
        self.stopped = False

    def _run(self):
        sleep = _native("time", "sleep")
        while not self.stopped:
            for _ in range(int(self.interval)):
                if self.stopped:
                    return
                sleep(1)
            try:
                self.store.heartbeat(self.job_id)
            except Exception:  # pylint: disable=W0703
                log.warning("project_restore: heartbeat failed for job %s", self.job_id)

    def start(self):
        _native("_thread", "start_new_thread")(self._run, ())
        return self

    def stop(self):
        self.stopped = True


def apply_job(  # pylint: disable=R0912,R0913,R0914,R0915
        raw_connection, job, spool_path, master_key, storage_client=None,
        max_archive_bytes=None, database=None, lock_timeout=None,
):
    """ Apply the spooled artifact of a job, return the response body of a synchronous restore

    job["options"] carries what the request validated and resolved: mode, flags,
    owner remap ids, project members, chat context and attachment settings.
    """
    options = job["options"]
    artifact = job["artifact"]
    schema = options["schema"]
    full_mode = options["mode"] == "full"
    dry_run = options.get("dry_run", False)
    #
    archive = None
    archive_spool = None
    try:
        open_bytes = _byte_chunks(spool_path)
        if artifact.get("encrypted"):
            open_bytes = backup_crypto.wrap_decrypt(open_bytes, master_key)
        #
        raw_head = _read_head(open_bytes, HEADER_SCAN_BYTES)
        manifest = None
        if chat_backup.is_zip(raw_head):
            if artifact.get("encrypted"):
                # A ZIP needs random access: decrypted once to a temp file
                archive_spool = tempfile.TemporaryFile()  # pylint: disable=R1732
                for chunk in open_bytes():
                    archive_spool.write(chunk)
                archive_spool.seek(0)
                source = archive_spool
            else:
                source = open(spool_path, "rb")  # pylint: disable=R1732
                archive_spool = source
            archive, _, manifest = open_backup_zip(source, max_archive_bytes)
            open_bytes = iter_zip_sql(archive)
            raw_head = _read_head(open_bytes, HEADER_SCAN_BYTES)
        #
        head = raw_head.decode("utf-8", "replace")
        kind = detect_artifact_kind(head)
        if kind is None or kind != artifact["kind"]:
            raise RestoreFailed({"ok": False, "error": "unrecognized backup file", "artifact": artifact}, 400)
        #
        restore_chats = options.get("restore_chats") or chat_backup.CHATS_NONE
        # Without the files in the backup, attachments can only be re-linked
        if restore_chats == chat_backup.CHATS_WITH_ATTACHMENTS and not artifact.get("has_attachment_files"):
            restore_chats = chat_backup.CHATS_WITHOUT_ATTACHMENTS
        #
        if kind == KIND_SAFE:
            handler = None
            if artifact.get("chats_included", chat_backup.CHATS_NONE) != chat_backup.CHATS_NONE \
                    and restore_chats != chat_backup.CHATS_NONE and storage_client is not None:
                handler = AttachmentRestorer(
                    storage_client, options["attachment_bucket"],
                    archive=archive, manifest=manifest,
                    with_files=restore_chats == chat_backup.CHATS_WITH_ATTACHMENTS,
                    retention_days=options.get("attachment_retention_days"),
                )
            result = restore_safe_backup(
                raw_connection,
                open_chunks=_text_chunks(open_bytes),
                schema=schema,
                tables=options.get("tables") or [],
                include_parents=options.get("include_parents", False),
                truncate=options.get("truncate", False),
                dry_run=dry_run,
                denied_tables=SAFE_RESTORE_DENIED_TABLES if options.get("restrict_tables") else (),
                owner_user_id=options.get("owner_user_id"),
                owner_project_id=options.get("owner_project_id"),
                source_project_id=options.get("source_project_id"),
                member_user_ids=options.get("member_user_ids"),
                backup_chats=artifact.get("chats_included", chat_backup.CHATS_NONE),
                restore_chats=restore_chats,
                chat_context=options.get("chat_context"),
                attachment_handler=handler,
                skill_file_handler=SkillFileRestorer(lambda: storage_client, archive)
                if storage_client is not None else None,
                project_id=job["project_id"],
                lock_timeout=lock_timeout,
            )
            log.info(
                "project_restore_applied: project %s (job=%s, dry_run=%s, chats_included=%s,"
                " restore_chats=%s, chats=%s, attachments=%s, skill_files=%s)",
                job["project_id"], job["id"], dry_run, artifact.get("chats_included"), restore_chats,
                result.get("chats"), {
                    k: v for k, v in (result.get("attachments") or {}).items() if k != "failed_names"
                }, restore_summary_counts(result.get("skill_files")),
            )
        else:
            with raw_connection.cursor() as cursor:
                known_settings = server_settings(cursor)
            raw_connection.rollback()
            # psql commits on EOF: a frame failing halfway must be caught first
            if artifact.get("encrypted"):
                for _ in open_bytes():
                    pass
            result = run_psql(
                open_chunks=open_bytes, schema=schema,
                host=database["host"], port=database["port"], user=database["user"],
                password=database["password"], database=database["database"],
                dry_run=dry_run, known_settings=known_settings, lock_timeout=lock_timeout,
            )
            if result["return_code"] != 0 and not dry_run:
                raise RestoreFailed(
                    {"ok": False, "error": "psql failed", "artifact": artifact, "result": result}, 400,
                )
    except RestoreFailed:
        raise
    except ValueError as exc:
        log.warning("project_restore: rejected artifact for %s (job %s): %s", schema, job["id"], exc)
        raise RestoreFailed({"ok": False, "error": str(exc)}, 400) from exc
    except Exception as exc:  # pylint: disable=W0703
        log.exception("project_restore: failed for %s (job %s)", schema, job["id"])
        raise RestoreFailed({"ok": False, "error": "restore failed", "detail": str(exc)}, 500) from exc
    finally:
        if archive is not None:
            archive.close()
        if archive_spool is not None:
            archive_spool.close()
    #
    result["mode"] = "partial" if options.get("tables") else "full"
    return {"ok": True, "artifact": artifact, "result": result}


class Workers:
    """ Restore worker processes of this pylon, at most `limit` at a time

    A worker must not outlive its pylon: once its job is failed (on the next
    boot or by the reaper) the project is free, and a retry would restore it
    twice at once. The worker exits when the pylon end of its pipe closes, and
    stop_all() kills the ones still running when the pylon stops.
    """

    def __init__(self, limit):
        self.limit = limit
        self.running = {}  # job_id -> Popen

    def stop_all(self):
        for job_id, process in list(self.running.items()):
            if process.poll() is None:
                log.warning("project_restore: stopping the worker of job %s", job_id)
                kill_worker(process.pid)

    def busy(self):
        self.running = {key: process for key, process in self.running.items() if process.poll() is None}
        return len(self.running) >= self.limit

    def start(self, job_id, payload, on_exit, open_storage=None):
        """ Start the worker for a job; on_exit(job_id, return_code) runs once it ends

        The worker reads its payload as the first stdin line, then talks to
        the storage served here: requests on its stdout, replies on its stdin.
        open_storage() builds the platform storage client on the first call.
        """
        process = subprocess.Popen(  # pylint: disable=R1732
            [sys.executable, "-I", WORKER_PATH],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=None,
            close_fds=True, start_new_session=True,
        )
        _register_external_pid(process.pid)
        try:
            process.stdin.write((json.dumps(payload) + "\n").encode("utf-8"))
            process.stdin.flush()
        except Exception:
            process.kill()
            raise
        self.running[job_id] = process
        #
        def watch():
            try:
                # Storage calls run here, on this pylon's MinioClient; the
                # worker blocks on each reply, so this is the only reader
                restore_storage.serve(open_storage, (line.decode("utf-8") for line in process.stdout),
                                      process.stdin)
            except Exception:  # pylint: disable=W0703
                log.exception("project_restore: storage channel of job %s failed", job_id)
            finally:
                for stream in (process.stdin, process.stdout):
                    try:
                        stream.close()
                    except Exception:  # pylint: disable=W0703
                        pass
            return_code = process.wait()
            _register_external_pid(process.pid, present=False)
            self.running.pop(job_id, None)
            on_exit(job_id, return_code)
        #
        import threading  # pylint: disable=C0415
        threading.Thread(target=watch, name="project-restore-{}".format(job_id), daemon=True).start()
        return process.pid


def kill_worker(pid):
    """ SIGKILL a worker and anything it started (psql): it leads its own process group """
    import signal  # pylint: disable=C0415
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def worker_alive(pid):
    """ Whether pid is still a running restore worker (not a recycled pid) """
    try:
        with open("/proc/{}/cmdline".format(int(pid)), "rb") as source:
            return os.path.basename(WORKER_PATH).encode() in source.read()
    except (OSError, ValueError, TypeError):
        return False


def watch_parent(interval=2):
    """ Worker side: exit as soon as the pylon that started it is gone

    getppid() changes when the parent dies (the worker is re-parented), and
    works whatever the restore is doing - including long SQL phases between
    storage calls. The restore transaction is rolled back by the server when
    the connection closes.
    """
    parent = os.getppid()
    sleep = _native("time", "sleep")

    def run():
        while True:
            sleep(interval)
            if os.getppid() != parent:
                log.error("project_restore: the pylon that started this worker is gone, stopping")
                os._exit(3)  # pylint: disable=W0212
    _native("_thread", "start_new_thread")(run, ())


def _register_external_pid(pid, present=True):
    """ Keep pylon's zombie reaper off the worker: its watcher waits for it """
    try:
        from tools import context  # pylint: disable=E0401,C0415
        reaper = context.zombie_reaper
    except Exception:  # pylint: disable=W0703
        return
    if present:
        reaper.external_pids.add(pid)
    else:
        reaper.external_pids.discard(pid)


def _connect(database):
    import psycopg2  # pylint: disable=E0401,C0415
    return psycopg2.connect(
        host=database["host"], port=database["port"], user=database["user"],
        password=database["password"], dbname=database["database"],
    )


def run_worker(payload, storage_client):
    """ Worker body: runs in restore_worker.py, returns the exit status """
    job_id = payload["job_id"]
    spool_path = payload["spool_path"]
    database = payload["database"]
    schema = payload["job_schema"]
    settings = payload["settings"]
    #
    store = restore_jobs.JobStore(lambda: job_connection, schema)
    job_connection = _connect(database)
    heartbeat = None
    connection = None
    try:
        job = store.get(job_id)
        if job is None or not store.start(job_id):
            log.warning("project_restore: job %s is not queued any more", job_id)
            return 0
        #
        heartbeat = Heartbeat(
            restore_jobs.JobStore(lambda: _connect(database), schema, release=lambda item: item.close()),
            job_id,
        ).start()
        connection = _connect(database)
        try:
            body = apply_job(
                connection, job, spool_path, backup_crypto.configured_master_key(),
                storage_client,
                max_archive_bytes=settings["max_archive_bytes"],
                database=database,
                lock_timeout=settings["lock_timeout"],
            )
        except RestoreFailed as failure:
            store.fail(job_id, failure.body.get("error"), failure.status_code, failure.body)
            return 0
        store.finish(job_id, body, 200)
        return 0
    except Exception as exc:  # pylint: disable=W0703
        log.exception("project_restore: job %s crashed", job_id)
        try:
            store.fail(job_id, "restore failed", 500, {"ok": False, "error": "restore failed", "detail": str(exc)})
        except Exception:  # pylint: disable=W0703
            pass
        return 1
    finally:
        if heartbeat is not None:
            heartbeat.stop()
        for item in (connection, job_connection):
            if item is not None:
                try:
                    item.close()
                except Exception:  # pylint: disable=W0703
                    pass
        remove_spool(spool_path)
