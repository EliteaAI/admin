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

""" API """

import time
import urllib.parse

import flask  # pylint: disable=E0401

from pylon.core.tools import log  # pylint: disable=E0611,E0401

from tools import auth, api_tools, register_openapi  # pylint: disable=E0401
from tools import context  # pylint: disable=E0401

from tools import constants as c  # pylint: disable=E0401

from ...utils import backup_crypto
from ...utils import chat_backup
from ...utils import restore_jobs
from ...utils import restore_runner
from ...utils.project_restore import (
    KIND_SAFE, KIND_PG_DUMP, INSPECT_BYTES, inspect_head, pg_dump_schema,
)


PROMPT_LIB_MODE = "prompt_lib"

FULL_MODE_PERMISSION = "projects.projects.restore.full"

PROJECT_BACKUP_PERMISSION = "models.project_backup"

PROJECT_RESTORE_PERMISSION = "models.project_backup.restore"

TRUE_VALUES = ("1", "true", "yes", "on")

SAFE_MODES = ("safe", "sanitized", "default")
FULL_MODES = ("full", "raw", "as_is")

DEFAULT_MAX_ARCHIVE_MB = 4096

WAIT_POLL_SECONDS = 1


def _flag(name, default=False):
    raw = flask.request.form.get(name)
    if raw is None:
        raw = flask.request.args.get(name)
    if raw is None:
        return default
    return str(raw).strip().lower() in TRUE_VALUES


def _param(name):
    value = flask.request.form.get(name)
    if value is None:
        value = flask.request.args.get(name)
    return value or ""


def _is_same_site_request():
    """ Reject a browser request initiated from another site (CSRF)

    Sec-Fetch-Site and Origin are set by the browser itself and can not be
    forged by page script. A non-browser client (curl, CI) sends neither and
    stays gated by permissions only, as before.
    """
    fetch_site = flask.request.headers.get("Sec-Fetch-Site")
    if fetch_site is not None:
        return fetch_site.strip().lower() in ("same-origin", "same-site")
    #
    origin = flask.request.headers.get("Origin")
    if not origin:
        return True
    #
    try:
        source = urllib.parse.urlsplit(origin).hostname
    except ValueError:
        return False
    #
    return bool(source) and source == flask.request.host.split(":")[0]


def _is_own_personal_project(project_id):
    """ A private project is created with its owner as editor / viewer / monitor,
    never as its admin, so restoring into it is authorized by ownership instead """
    current_user = auth.current_user()
    user_id = current_user.get("id") if current_user else None
    #
    if not user_id:
        return False
    #
    try:
        personal_project_id = context.rpc_manager.timeout(2). \
            projects_get_personal_project_id(user_id)
    except Exception:  # pylint: disable=W0703
        log.exception("project_restore: failed to resolve the personal project of user %s", user_id)
        return False
    #
    return personal_project_id == project_id


def _project_member_ids(project_id):
    """ Users of the project, or None when they can not be resolved """
    try:
        return context.rpc_manager.timeout(5).admin_get_users_ids_in_project(project_id=project_id)
    except Exception:  # pylint: disable=W0703
        log.exception("project_restore: failed to resolve the users of project %s", project_id)
        return None


def _requested_restore_chats():
    value = _param("restore_chats").strip().lower() or chat_backup.CHATS_NONE
    return value if value in chat_backup.CHAT_OPTIONS else None


def _attachment_settings(project_id):
    """ (bucket, retention days) chat attachments of the project are stored with """
    try:
        from tools import VaultClient  # pylint: disable=E0401,C0415
        secrets = VaultClient(project_id).get_all_secrets()
        return (
            secrets.get("default_attachment_bucket") or "attachments",
            int(secrets.get("chat_bucket_retention_days", 365)),
        )
    except Exception:  # pylint: disable=W0703
        return "attachments", 365


def _storage_client(project_id):
    """ The platform storage client of the project, whatever engine is configured """
    from tools import MinioClient  # pylint: disable=E0401,C0415
    return MinioClient.from_project_id(project_id)


def _instance():
    """ Stable across restarts of the same pod, unlike context.id """
    return getattr(context, "node_name", None) or "pylon"


def _read_upload_head(source):
    """ First bytes of the upload, and the stream positioned after them """
    head = bytearray()
    while len(head) < INSPECT_BYTES:
        chunk = source.stream.read(INSPECT_BYTES - len(head))
        if not chunk:
            break
        head += chunk
    return bytes(head)


def _drain(stream):
    """ Bytes left in the upload stream, read and discarded """
    size = 0
    while True:
        chunk = stream.read(restore_runner.READ_CHUNK)
        if not chunk:
            return size
        size += len(chunk)


class _PrefixedStream:  # pylint: disable=R0903
    """ The upload stream with the bytes already read put back in front """

    def __init__(self, prefix, stream):
        self.prefix = prefix
        self.stream = stream

    def read(self, size=-1):
        if self.prefix:
            data, self.prefix = self.prefix[:size], self.prefix[size:]
            return data
        return self.stream.read(size)


def _wait_for_job(store, job_id):
    """ The synchronous response of an API client that asked to wait """
    while True:
        job = store.get(job_id)
        if job is None:
            return {"ok": False, "error": "restore job disappeared"}, 500
        if job["status"] == restore_jobs.STATUS_DONE:
            return job["result"], 200
        if job["status"] == restore_jobs.STATUS_FAILED:
            return job["result"] or {"ok": False, "error": job["error"]}, job["status_code"] or 500
        time.sleep(WAIT_POLL_SECONDS)


def apply_uploaded_backup(  # pylint: disable=R0911,R0912,R0913,R0914,R0915
        module, project_id, allow_pg_dump=True, allow_mismatch_override=True, restrict_tables=False,
        policy=backup_crypto.POLICY_ENABLED,
):
    """ Validate the uploaded artifact and start applying it in a forked task """
    if not _is_same_site_request():
        return {"ok": False, "error": "access_denied"}, 403
    #
    requested_mode = _param("mode").strip().lower() or "safe"
    #
    if requested_mode in SAFE_MODES:
        full_mode = False
    elif requested_mode in FULL_MODES:
        full_mode = True
    else:
        return {"ok": False, "error": "unknown mode"}, 400
    #
    if full_mode:
        if not allow_pg_dump:
            return {
                "ok": False,
                "error": "raw pg_dump artifacts can only be restored by platform admins",
            }, 403
        current_permissions = auth.resolve_permissions(mode="administration")
        if not auth.has_access(current_permissions, [FULL_MODE_PERMISSION]):
            return {"ok": False, "error": "access_denied"}, 403
    #
    if "file" not in flask.request.files:
        return {"ok": False, "error": "no file provided"}, 400
    #
    tables = [item.strip() for item in _param("tables").split(",") if item.strip()]
    include_parents = _flag("include_parents")
    truncate = _flag("truncate")
    dry_run = _flag("dry_run")
    inspect_only = _flag("inspect")
    # A client that follows the job asks for it; any other client (an older UI,
    # curl, CI) gets the synchronous response it always got
    wait = not _flag("background")
    allow_mismatch = _flag("allow_project_mismatch") if allow_mismatch_override else False
    restore_chats = _requested_restore_chats()
    if restore_chats is None:
        return {"ok": False, "error": "unknown restore_chats option"}, 400
    #
    from tools import project_constants as pc  # pylint: disable=E0401,C0415
    schema = pc["PROJECT_SCHEMA_TEMPLATE"].format(project_id)
    #
    source = flask.request.files["file"]
    filename = source.filename
    head = _read_upload_head(source)
    if not head:
        return {"ok": False, "error": "empty file"}, 400
    #
    # The envelope is checked on raw bytes, before anything is decoded: a
    # successful decrypt is what proves the artifact came from a setup holding
    # this SECRETS_MASTER_KEY, so nothing downstream ever sees a hand-written
    # file. The first frame is verified here, every other one in the task.
    #
    encrypted = backup_crypto.is_encrypted(head[:len(backup_crypto.ENVELOPE_MAGIC)])
    master_key = backup_crypto.configured_master_key()
    if encrypted and master_key is None:
        return {
            "ok": False,
            "error": "this backup is encrypted but SECRETS_MASTER_KEY is not "
                     "configured on this setup",
        }, 400
    if not encrypted and policy == backup_crypto.POLICY_REQUIRED:
        return {
            "ok": False,
            "error": "only encrypted backups can be restored on this setup; "
                     "export the project again and upload the .sql.enc or .zip.enc file",
        }, 400
    #
    try:
        artifact, head_text = inspect_head(head, master_key, with_text=True)
    except ValueError as exc:
        log.warning("project_restore: rejected artifact for %s: %s", schema, exc)
        return {"ok": False, "error": str(exc)}, 400
    artifact["filename"] = filename
    #
    # The dialog reads what a file carries as soon as it is picked. A client
    # that sends only the first bytes reports the real size; one that sends the
    # whole file gets it measured, as before
    if inspect_only:
        try:
            artifact["size"] = int(_param("size"))
        except ValueError:
            artifact["size"] = len(head) + _drain(source.stream)
        return {"ok": True, "inspect": True, "artifact": artifact}, 200
    #
    kind = artifact["kind"]
    source_project = artifact.get("project_id")
    if isinstance(source_project, int) and source_project != project_id \
            and not allow_mismatch:
        if allow_mismatch_override:
            error = "artifact belongs to project {}; pass " \
                    "allow_project_mismatch=true to restore it into project {}".format(
                        source_project, project_id)
        else:
            error = "artifact belongs to project {} and can not be restored " \
                    "into project {}".format(source_project, project_id)
        return {"ok": False, "error": error, "artifact": artifact}, 409
    #
    # Entities coming from another project would stay attributed to its
    # users, so ownership moves to whoever performs the restore. The owner
    # columns that hold a project rather than a user move to this project.
    #
    current_user = auth.current_user()
    current_user_id = current_user.get("id") if current_user else None
    owner_user_id = None
    owner_project_id = None
    source_project_id = None
    if isinstance(source_project, int) and source_project != project_id:
        owner_user_id = current_user_id
        owner_project_id = project_id
        source_project_id = source_project
    #
    # The requested mode decides how the artifact is applied, so the detected
    # kind has to agree with it: an unexpected file is reported instead of
    # silently taking the other path.
    if full_mode and kind != KIND_PG_DUMP:
        return {
            "ok": False,
            "error": "this file is a redacted project backup, not a raw pg_dump;"
                     " restore it in safe mode",
            "artifact": artifact,
        }, 400
    #
    if not full_mode and kind != KIND_SAFE:
        return {
            "ok": False,
            "error": "this file is a raw pg_dump and can not be restored in safe mode",
            "artifact": artifact,
        }, 400
    #
    if full_mode and tables:
        return {
            "ok": False,
            "error": "partial restore is not supported for pg_dump artifacts",
        }, 400
    #
    # A plain pg_dump rebuilds the schema it was taken from: it carries its
    # own CREATE SCHEMA, fully qualified names and a search_path reset, so
    # the target search_path is ignored and the restore would recreate the
    # source project instead of filling this one.
    #
    if full_mode:
        dump_schema = pg_dump_schema(head_text)
        artifact["dump_schema"] = dump_schema
        #
        if dump_schema is not None and dump_schema != schema:
            return {
                "ok": False,
                "error": "this pg_dump rebuilds schema {} and can not be retargeted "
                         "at {}; restore it in safe mode instead".format(
                             dump_schema, schema),
                "artifact": artifact,
            }, 400
    #
    connection = context.db.engine.raw_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "select 1 from information_schema.schemata where schema_name = %s",
                (schema,),
            )
            if cursor.fetchone() is None:
                return {"ok": False, "error": "project schema not found"}, 404
        connection.rollback()
    finally:
        connection.close()
    #
    store = module.restore_job_store()
    active = store.active(project_id)
    if active is not None:
        return {"ok": False, "error": "restore_in_progress", "job_id": active["id"]}, 409
    #
    # Everything the worker needs from RPC or Vault is resolved here: it does
    # not call RPC. Its storage calls (chat attachments) are served by this
    # pylon on MinioClient.
    with_chats = artifact.get("chats_included", chat_backup.CHATS_NONE) != chat_backup.CHATS_NONE \
        and restore_chats != chat_backup.CHATS_NONE
    bucket, retention_days = None, None
    if kind == KIND_SAFE and with_chats:
        bucket, retention_days = _attachment_settings(project_id)
    #
    options = {
        "schema": schema,
        "mode": "full" if full_mode else "safe",
        "tables": tables,
        "include_parents": include_parents,
        "truncate": truncate,
        "dry_run": dry_run,
        "restrict_tables": restrict_tables,
        "restore_chats": restore_chats,
        "owner_user_id": owner_user_id,
        "owner_project_id": owner_project_id,
        "source_project_id": source_project_id,
        "member_user_ids": _project_member_ids(project_id) if kind == KIND_SAFE else None,
        "chat_context": {
            "restorer_id": current_user_id,
            "source_project_id": source_project if isinstance(source_project, int) else None,
            "target_project_id": project_id,
        },
        "attachment_bucket": bucket,
        "attachment_retention_days": retention_days,
    }
    #
    try:
        spool_path, size = restore_runner.spool_upload(
            _PrefixedStream(head, source.stream), module.restore_settings["spool_dir"],
        )
    except OSError:
        log.exception("project_restore: could not spool the upload for %s", schema)
        return {"ok": False, "error": "restore failed", "detail": "could not store the upload"}, 500
    artifact["size"] = size
    #
    try:
        job = store.create(
            project_id=project_id, user_id=current_user_id, mode=options["mode"],
            options=options, artifact=artifact, instance=_instance(),
        )
    except restore_jobs.RestoreInProgress as busy:
        restore_runner.remove_spool(spool_path)
        return {"ok": False, "error": "restore_in_progress", "job_id": busy.job_id}, 409
    #
    log.info(
        "project_restore: starting job %s, %s artifact to %s (%s, dry_run=%s)",
        job["id"], kind, schema, "partial" if tables else "full", dry_run,
    )
    #
    if module.restore_workers.busy():
        restore_runner.remove_spool(spool_path)
        store.fail(job["id"], "restore_capacity_busy", 503)
        return {
            "ok": False, "error": "restore_capacity_busy",
            "detail": "another restore is running on this server; retry in a minute",
        }, 503
    #
    payload = {
        "job_id": job["id"],
        "spool_path": spool_path,
        "job_schema": module.restore_job_schema,
        "database": module.restore_worker_database(),
        "settings": {
            "max_archive_bytes": module.restore_settings["max_archive_bytes"],
            "lock_timeout": module.restore_settings["lock_timeout"],
        },
        "master_key": master_key.decode("utf-8") if isinstance(master_key, bytes) else master_key,
        "with_storage": kind == KIND_SAFE,
    }
    try:
        task_id = str(module.restore_workers.start(
            job["id"], payload, _on_worker_exit(module), open_storage=lambda: _storage_client(project_id),
        ))
    except Exception:  # pylint: disable=W0703
        log.exception("project_restore: could not start the worker for job %s", job["id"])
        restore_runner.remove_spool(spool_path)
        store.fail(job["id"], "restore failed", 500,
                   {"ok": False, "error": "restore failed", "detail": "could not start the restore worker"})
        return {"ok": False, "error": "restore failed", "detail": "could not start the restore worker"}, 500
    store.attach_task(job["id"], task_id)
    #
    if wait:
        return _wait_for_job(store, job["id"])
    return {"ok": True, "job_id": job["id"], "status": restore_jobs.STATUS_RUNNING, "artifact": artifact}, 202


def _on_worker_exit(module):
    """ A worker that died without writing its result leaves the job failed """
    def callback(job_id, return_code):
        try:
            job = module.restore_job_store().get(job_id)
            if job is not None and job["status"] in restore_jobs.ACTIVE_STATUSES:
                log.error("project_restore: worker of job %s exited with %s", job_id, return_code)
                module.restore_job_store().fail(
                    job_id, restore_jobs.STALE_ERROR, 500,
                    {"ok": False, "error": "restore failed", "detail": restore_jobs.STALE_ERROR},
                )
        except Exception:  # pylint: disable=W0703
            log.exception("project_restore: could not check job %s after its worker exited", job_id)
    return callback


def job_status(module, project_id, job_id):
    job = module.restore_job_store().get(job_id, project_id=project_id)
    if job is None:
        return {"ok": False, "error": "restore job not found"}, 404
    return restore_jobs.public_view(job), 200


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=R0903
    """ API """

    @register_openapi(
        name="Restore Project Backup",
        description="Restore a backup produced by the project backup endpoint into a "
                    "project schema. Upload the .sql.enc or .zip.enc (or plain .sql / .zip) file as multipart "
                    "form field 'file'. An encrypted artifact is decrypted and verified "
                    "with a key derived from this setup's SECRETS_MASTER_KEY, so only "
                    "artifacts produced by a setup sharing that key can be restored. "
                    "Without 'tables' the whole artifact is applied (full restore); with "
                    "'tables' only the listed tables are applied (partial restore). "
                    "In the default 'safe' mode the artifact is applied statement by "
                    "statement in one transaction, and only redacted project backups "
                    "are accepted. The 'full' mode pipes a raw pg_dump artifact to psql "
                    "and requires the 'projects.projects.restore.full' permission. "
                    "The uploaded file has to match the requested mode.",
        parameters=[
            {"name": "project_id", "in": "path", "schema": {"type": "integer"},
             "description": "Target project ID."},
            {"name": "mode", "in": "query",
             "schema": {"type": "string", "enum": ["safe", "full"], "default": "safe"},
             "description": "safe (default, redacted backup) or full (raw pg_dump)."},
            {"name": "tables", "in": "query", "schema": {"type": "string"},
             "description": "Comma-separated tables to restore. Empty means full restore."},
            {"name": "include_parents", "in": "query", "schema": {"type": "boolean"},
             "description": "Also restore the FK parents of the listed tables."},
            {"name": "truncate", "in": "query", "schema": {"type": "boolean"},
             "description": "Empty the in-scope tables first (TRUNCATE ... CASCADE) "
                            "instead of merging with ON CONFLICT DO NOTHING."},
            {"name": "background", "in": "query", "schema": {"type": "boolean"},
             "description": "Answer 202 with a job_id right away and apply the backup in a worker; "
                            "follow it with the project_restore_job endpoint. Without it the request "
                            "waits for the restore and answers with its result, as before."},
            {"name": "dry_run", "in": "query", "schema": {"type": "boolean"},
             "description": "Execute inside a transaction and roll it back."},
            {"name": "allow_project_mismatch", "in": "query", "schema": {"type": "boolean"},
             "description": "Required when the artifact was taken from another project."},
        ],
    )
    @auth.decorators.check_api({
        "permissions": ["projects.projects.restore.apply"],
        "recommended_roles": {
            "administration": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
            "default": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
        }})
    def post(self, project_id: int, **kwargs):
        """ Process POST """
        _ = kwargs
        return apply_uploaded_backup(
            self.module, project_id, policy=backup_crypto.handler_policy(self),
        )


class PromptLibAPI(api_tools.APIModeHandler):  # pylint: disable=R0903
    """ API """

    @register_openapi(
        name="Restore Project Backup (project scope)",
        description="Restore a redacted (safe) backup into this project. Upload the "
                    ".sql.enc or .zip.enc (or plain .sql / .zip) file as multipart form field 'file'. An encrypted "
                    "artifact is decrypted and verified with a key derived from this "
                    "setup's SECRETS_MASTER_KEY, so only artifacts produced by a setup "
                    "sharing that key can be restored. Only the 'safe' mode is "
                    "available here, so only redacted project backups are accepted; raw "
                    "pg_dump restores stay in the administration API. "
                    "An artifact taken from another project is rejected unless "
                    "'allow_project_mismatch=true' is passed. Without 'tables' the whole "
                    "artifact is applied; with 'tables' only the listed tables.",
        parameters=[
            {"name": "project_id", "in": "path", "schema": {"type": "integer"},
             "description": "Target project ID."},
            {"name": "tables", "in": "query", "schema": {"type": "string"},
             "description": "Comma-separated tables to restore. Empty means full restore."},
            {"name": "include_parents", "in": "query", "schema": {"type": "boolean"},
             "description": "Also restore the FK parents of the listed tables."},
            {"name": "truncate", "in": "query", "schema": {"type": "boolean"},
             "description": "Empty the in-scope tables first (TRUNCATE ... CASCADE) "
                            "instead of merging with ON CONFLICT DO NOTHING."},
            {"name": "background", "in": "query", "schema": {"type": "boolean"},
             "description": "Answer 202 with a job_id right away and apply the backup in a worker; "
                            "follow it with the project_restore_job endpoint. Without it the request "
                            "waits for the restore and answers with its result, as before."},
            {"name": "dry_run", "in": "query", "schema": {"type": "boolean"},
             "description": "Execute inside a transaction and roll it back."},
            {"name": "allow_project_mismatch", "in": "query", "schema": {"type": "boolean"},
             "description": "Required when the artifact was taken from another project."},
            {"name": "inspect", "in": "query", "schema": {"type": "boolean"},
             "description": "Only read the artifact header and return what it carries. The first "
                            "1 MiB of the file is enough; pass 'size' with the real file size then."},
            {"name": "size", "in": "query", "schema": {"type": "integer"},
             "description": "With inspect: size of the whole file when only its start is uploaded."},
            {"name": "restore_chats", "in": "query",
             "schema": {"type": "string", "enum": list(chat_backup.CHAT_OPTIONS), "default": "none"},
             "description": "Restore the chats of a backup that carries them: "
                            "without_attachments keeps attachment messages whose file the "
                            "project still has, with_attachments uploads the files of a ZIP "
                            "backup. Chats with a uuid the project already has are skipped."},
        ],
    )
    @auth.decorators.check_api({
        "permissions": [PROJECT_BACKUP_PERMISSION],
        "recommended_roles": {
            "administration": {"super_admin": True, "admin": True, "viewer": False, "editor": True},
            "default": {"super_admin": True, "admin": True, "viewer": False, "editor": True},
        }})
    def post(self, project_id: int, **kwargs):
        """ Process POST """
        _ = kwargs
        # Safe artifacts may be restored across projects via allow_project_mismatch=true;
        # authorization is enforced on the TARGET project (models.project_backup.restore
        # on project_id in the URL), so the caller must hold that permission there --
        # or own the target, which is how a private project reaches its own restore.
        #
        current_permissions = auth.resolve_permissions(
            mode=PROMPT_LIB_MODE, project_id=project_id,
        )
        if not auth.has_access(current_permissions, [PROJECT_RESTORE_PERMISSION]) \
                and not _is_own_personal_project(project_id):
            return {"ok": False, "error": "access_denied",
                    "required": [PROJECT_RESTORE_PERMISSION]}, 403
        #
        # Tables a safe backup never exports are refused here instead of being
        # skipped: a hand-written artifact could otherwise insert role /
        # role_permission / user_role rows and grant itself permissions.
        #
        return apply_uploaded_backup(
            self.module, project_id, allow_pg_dump=False, allow_mismatch_override=True,
            restrict_tables=True, policy=backup_crypto.handler_policy(self),
        )


class API(api_tools.APIBase):  # pylint: disable=R0903
    """ API """

    url_params = [
        "<string:mode>/<int:project_id>",
    ]

    mode_handlers = {
        'administration': AdminAPI,
        PROMPT_LIB_MODE: PromptLibAPI,
    }
