"""Unit tests for EL-7498 - project restore as a background job.

Covers:
  - utils/project_restore.py: header-only inspect (AC-9), lock window (AC-6)
  - utils/chat_restore.py: attachments uploaded before the transaction (AC-6, AC-8)
"""
import importlib.util
import io
import json
import os
import pathlib
import sys
import types

import pytest


UTILS_PATH = pathlib.Path(__file__).resolve().parents[2] / "utils"
PACKAGE = "_admin_utils_restore_job"

MASTER_KEY = b"test-master-key-for-restore-jobs"


def _find_artifact_crypto():
    """ The shared plugin's artifact_crypto next to this plugin, or None

    CI checks out this plugin alone, so the shared plugin (and cryptography)
    may be missing: the tests that really encrypt are skipped then.
    """
    plugin_root = UTILS_PATH.parent
    for directory in (plugin_root, *plugin_root.parents):
        candidate = directory / "shared" / "tools" / "artifact_crypto.py"
        if candidate.is_file():
            try:
                import cryptography  # noqa: F401  pylint: disable=C0415,W0611
            except ImportError:
                return None
            return candidate
    return None


ARTIFACT_CRYPTO_PATH = _find_artifact_crypto()
needs_crypto = pytest.mark.skipif(
    ARTIFACT_CRYPTO_PATH is None, reason="shared plugin or cryptography not available",
)


def _artifact_crypto_stand_in():
    """ Enough of tools.artifact_crypto for backup_crypto to import; nothing can be encrypted """
    module = types.ModuleType("tools.artifact_crypto")
    module.ENVELOPE_SUFFIX = ".enc"
    module.ENVELOPE_MIMETYPE = "application/octet-stream"
    module.CIPHER = "AES-256-GCM"
    module.KDF = "HKDF-SHA256"
    module.FRAME_SIZE = 1048576
    module.MAX_FRAME_SIZE = 8388608
    module.POLICY_DISABLED, module.POLICY_ENABLED, module.POLICY_REQUIRED = "disabled", "enabled", "required"
    module.POLICIES = (module.POLICY_DISABLED, module.POLICY_ENABLED, module.POLICY_REQUIRED)
    module.configured_master_key = lambda: None
    module.resolve_policy = lambda config, key: module.POLICY_ENABLED

    class Envelope:  # pylint: disable=R0903
        def __init__(self, magic, *args):
            self.magic = magic

        def is_encrypted(self, head):
            if isinstance(head, str):
                head = head.encode("utf-8", "replace")
            return head.startswith(self.magic)

        def _unavailable(self, *args, **kwargs):
            raise RuntimeError("artifact_crypto is not available in this run")

        key_id = iter_encrypt = iter_decrypt = wrap_decrypt = _unavailable

    module.Envelope = Envelope
    return module


def _load_utils():
    """Import the restore utils without a running pylon"""
    if "pylon.core.tools" not in sys.modules:
        tools = types.ModuleType("pylon.core.tools")
        tools.log = types.SimpleNamespace(
            info=lambda *a, **k: None, warning=lambda *a, **k: None,
            error=lambda *a, **k: None, exception=lambda *a, **k: None,
        )
        sys.modules.setdefault("pylon", types.ModuleType("pylon"))
        sys.modules.setdefault("pylon.core", types.ModuleType("pylon.core"))
        sys.modules["pylon.core.tools"] = tools
    #
    # backup_crypto imports tools.artifact_crypto from the shared plugin
    tools_module = sys.modules.setdefault("tools", types.ModuleType("tools"))
    if not hasattr(tools_module, "artifact_crypto"):
        if ARTIFACT_CRYPTO_PATH is None:
            module = _artifact_crypto_stand_in()
        else:
            spec = importlib.util.spec_from_file_location("tools.artifact_crypto", ARTIFACT_CRYPTO_PATH)
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
        sys.modules["tools.artifact_crypto"] = module
        tools_module.artifact_crypto = module
    #
    package = types.ModuleType(PACKAGE)
    package.__path__ = [str(UTILS_PATH)]
    sys.modules[PACKAGE] = package
    #
    modules = {}
    for name in ("project_backup", "chat_backup", "chat_restore", "project_restore", "backup_crypto"):
        spec = importlib.util.spec_from_file_location(
            "{}.{}".format(PACKAGE, name), UTILS_PATH / "{}.py".format(name),
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        modules[name] = module
    return modules


MODULES = _load_utils()
cb = MODULES["chat_backup"]
cr = MODULES["chat_restore"]
pb = MODULES["project_backup"]
pr = MODULES["project_restore"]
bc = MODULES["backup_crypto"]


# ---------- fixtures ----------

FILES = {
    ("attachments", "c1/report.pdf"): b"%PDF-1.4 report",
    ("attachments", "c1/cat.png"): b"\x89PNG cat",
}


def _header(extra=None):
    return pb._header(  # pylint: disable=W0212
        3, "Team", "p_3", "2026-10-16T00:00:00+00:00", True, ["applications"], [], {}, extra,
    )


def _sql_backup(rows=1):
    """ A safe backup whose body is large enough to span several encryption frames """
    body = "".join(
        "INSERT INTO \"applications\" (\"id\", \"name\") VALUES ({}, '{}') ON CONFLICT DO NOTHING;\n"
        .format(index, "x" * 200)
        for index in range(rows)
    )
    return (_header({"chats_included": cb.CHATS_NONE}) + body).encode("utf-8")


def _zip_backup():
    attachments = [
        {"bucket": b, "name": n, "size": len(c), "status": "ok"} for (b, n), c in FILES.items()
    ]
    info = cb.make_info(3, "Team", {"id": 1, "name": "Admin"}, cb.CHATS_WITH_ATTACHMENTS, {
        "chats_count": 4, "attachments": attachments,
    })
    sql = [_header({"chats_included": cb.CHATS_WITH_ATTACHMENTS}).encode(), b"INSERT INTO x VALUES (1);\n"]
    return b"".join(cb.iter_backup_zip(
        info, iter(sql), attachments, lambda bucket, name: FILES[(bucket, name)],
    ))


def _encrypt(data):
    return b"".join(bc.iter_encrypt(iter([data]), MASTER_KEY))


# ---------- AC-9: inspect from the first bytes ----------


class TestInspectHead:

    def test_plain_sql_slice(self):
        artifact = pr.inspect_head(_sql_backup(rows=20000)[:pr.INSPECT_BYTES], master_key=None)
        assert artifact["kind"] == pr.KIND_SAFE
        assert artifact["project_id"] == 3
        assert artifact["project_name"] == "Team"
        assert artifact["encrypted"] is False
        assert artifact["has_attachment_files"] is False

    @needs_crypto
    def test_encrypted_sql_slice_spanning_several_frames(self):
        data = _encrypt(_sql_backup(rows=20000))
        assert len(data) > pr.INSPECT_BYTES  # the slice cuts the envelope short
        artifact = pr.inspect_head(data[:pr.INSPECT_BYTES], master_key=MASTER_KEY)
        assert artifact["kind"] == pr.KIND_SAFE
        assert artifact["project_id"] == 3
        assert artifact["encrypted"] is True

    def test_zip_slice_reads_info_json_only(self):
        data = _zip_backup()
        artifact = pr.inspect_head(data[:512], master_key=None)
        assert artifact["kind"] == pr.KIND_SAFE
        assert artifact["project_id"] == 3
        assert artifact["chats_included"] == cb.CHATS_WITH_ATTACHMENTS
        assert artifact["chats_count"] == 4
        assert artifact["attachments_count"] == 2
        assert artifact["attachments_size"] == sum(len(c) for c in FILES.values())
        assert artifact["has_attachment_files"] is True

    @needs_crypto
    def test_encrypted_zip_slice(self):
        data = _encrypt(_zip_backup())
        artifact = pr.inspect_head(data[:pr.INSPECT_BYTES], master_key=MASTER_KEY)
        assert artifact["project_id"] == 3
        assert artifact["has_attachment_files"] is True
        assert artifact["encrypted"] is True

    @needs_crypto
    def test_encrypted_without_key_is_rejected(self):
        with pytest.raises(ValueError):
            pr.inspect_head(_encrypt(_sql_backup())[:pr.INSPECT_BYTES], master_key=None)

    def test_garbage_is_rejected(self):
        with pytest.raises(ValueError):
            pr.inspect_head(os.urandom(4096), master_key=None)

    @needs_crypto
    def test_tampered_first_frame_is_rejected(self):
        data = bytearray(_encrypt(_sql_backup()))
        data[-20] ^= 0xFF
        with pytest.raises(ValueError):
            pr.inspect_head(bytes(data), master_key=MASTER_KEY)


# ---------- AC-6: lock window ----------


class FakeCursor:
    def __init__(self, connection):
        self.connection = connection
        self.rowcount = 0
        self._result = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def close(self):
        pass

    def execute(self, sql, params=None):
        self.connection.events.append(("execute", sql, params))
        lowered = sql.lower()
        self.rowcount = 1 if lowered.startswith("insert") else 0
        if "from information_schema.tables" in lowered:
            self._result = [(table,) for table in self.connection.tables]
        elif "from information_schema.columns" in lowered and "is_nullable" in lowered:
            self._result = []
        elif "from information_schema.columns" in lowered:
            self._result = [
                (table, column) for table, columns in self.connection.tables.items() for column in columns
            ]
        else:
            self._result = []

    def fetchall(self):
        return self._result


class FakeConnection:
    def __init__(self):
        self.tables = {"applications": {"id", "name"}}
        self.events = []

    def cursor(self):
        return FakeCursor(self)

    def commit(self):
        self.events.append(("commit", None, None))

    def rollback(self):
        self.events.append(("rollback", None, None))

    def statements(self):
        return [sql for kind, sql, _ in self.events if kind == "execute"]


def _chunks():
    text = _sql_backup(rows=2).decode("utf-8")
    return lambda: iter([text])


class TestLockWindow:

    def test_lock_timeout_is_set_before_truncate(self):
        connection = FakeConnection()
        pr.restore_safe_backup(connection, _chunks(), "p_3", truncate=True, lock_timeout="30s")
        statements = connection.statements()
        timeout_index = next(i for i, sql in enumerate(statements) if "lock_timeout" in sql.lower())
        truncate_index = next(i for i, sql in enumerate(statements) if sql.startswith("TRUNCATE"))
        assert timeout_index < truncate_index
        assert any(params == ("30s",) for kind, sql, params in connection.events
                   if kind == "execute" and "lock_timeout" in sql.lower())

    def test_metadata_reads_do_not_keep_the_transaction_open(self):
        connection = FakeConnection()
        pr.restore_safe_backup(connection, _chunks(), "p_3", truncate=True, lock_timeout="30s")
        kinds = [(kind, sql) for kind, sql, _ in connection.events]
        first_write = next(i for i, (kind, sql) in enumerate(kinds)
                           if kind == "execute" and sql.lower().startswith("set local search_path"))
        assert ("rollback", None) in kinds[:first_write]

    def test_lock_not_available_becomes_a_clear_error(self):
        psycopg2 = pytest.importorskip("psycopg2")

        class LockedCursor(FakeCursor):
            def execute(self, sql, params=None):
                if sql.startswith("TRUNCATE"):
                    error = psycopg2.errors.LockNotAvailable("canceling statement due to lock timeout")
                    raise error
                super().execute(sql, params)

        connection = FakeConnection()
        connection.cursor = lambda: LockedCursor(connection)
        with pytest.raises(ValueError, match="in use"):
            pr.restore_safe_backup(connection, _chunks(), "p_3", truncate=True, lock_timeout="30s")
        assert ("rollback", None, None) in connection.events


# ---------- AC-6 / AC-8: attachments uploaded before the transaction ----------


class FakeStorage:
    def __init__(self, files=None):
        self.files = dict(files or {})
        self.buckets = {bucket for bucket, _ in self.files}
        self.removed = []
        self.uploads = []

    def list_files(self, bucket):
        return [{"name": name, "size": len(data)} for (b, name), data in self.files.items() if b == bucket]

    def list_bucket(self):
        return sorted(self.buckets)

    def create_bucket(self, bucket, bucket_type=None, retention_days=None):
        self.buckets.add(bucket)

    def upload_file(self, bucket, content, name):
        self.uploads.append((bucket, name))
        self.files[(bucket, name)] = content

    def remove_file(self, bucket, name):
        self.removed.append((bucket, name))
        self.files.pop((bucket, name), None)


class RecordingCursor:
    def __init__(self):
        self.executed = []

    def execute(self, sql, params=None):
        self.executed.append((sql, params))


def _restorer(storage):
    archive, _, manifest = cr.open_backup_zip(io.BytesIO(_zip_backup()), 10 ** 9)
    return cr.AttachmentRestorer(storage, "attachments", archive, manifest, with_files=True)


class TestAttachmentsBeforeTransaction:

    def test_prepare_uploads_and_call_does_not(self):
        storage = FakeStorage()
        restorer = _restorer(storage)
        restorer.prepare(dry_run=False)
        uploaded = list(storage.uploads)
        assert sorted(uploaded) == [("attachments", "c1/cat.png"), ("attachments", "c1/report.pdf")]
        #
        items = [{"id": 1, "bucket": "attachments", "name": "c1/report.pdf", "content": None}]
        summary = restorer(RecordingCursor(), items, dry_run=False)
        assert storage.uploads == uploaded
        assert summary["uploaded"] == 1
        assert summary["failed"] == 0

    def test_files_no_message_points_at_are_removed_after_commit(self):
        storage = FakeStorage()
        restorer = _restorer(storage)
        restorer.prepare(dry_run=False)
        items = [{"id": 1, "bucket": "attachments", "name": "c1/report.pdf", "content": None}]
        restorer(RecordingCursor(), items, dry_run=False)
        restorer.release_unused()
        assert storage.removed == [("attachments", "c1/cat.png")]
        assert ("attachments", "c1/report.pdf") in storage.files

    def test_dry_run_prepare_uploads_nothing(self):
        storage = FakeStorage()
        restorer = _restorer(storage)
        restorer.prepare(dry_run=True)
        assert storage.uploads == []

    def test_restore_prepares_attachments_before_the_transaction(self):
        events = []

        class Handler:
            def prepare(self, dry_run):
                events.append("prepare")

            def __call__(self, cursor, attachments, dry_run):
                return {"total": 0}

        connection = FakeConnection()
        original_cursor = connection.cursor

        def cursor():
            item = original_cursor()
            execute = item.execute

            def recording(sql, params=None):
                if sql.lower().startswith("set local search_path"):
                    events.append("transaction")
                execute(sql, params)
            item.execute = recording
            return item
        connection.cursor = cursor
        #
        text = _header({"chats_included": cb.CHATS_WITH_ATTACHMENTS}) + "SELECT 1;\n"
        try:
            pr.restore_safe_backup(
                connection, lambda: iter([text]), "p_3",
                backup_chats=cb.CHATS_WITH_ATTACHMENTS, restore_chats=cb.CHATS_WITH_ATTACHMENTS,
                attachment_handler=Handler(),
            )
        except (ValueError, KeyError):
            pass  # the fake catalog has no chat tables; only the order matters here
        assert events[:2] == ["prepare", "transaction"]


# ---------- review: pg_dump schema check reads the decrypted head ----------


class TestInspectText:

    PG_DUMP = (
        "--\n-- PostgreSQL database dump\n--\nSET statement_timeout = 0;\n"
        "CREATE SCHEMA p_5;\nCREATE TABLE p_5.applications (id integer);\n"
    ).encode("utf-8")

    @needs_crypto
    def test_encrypted_pg_dump_exposes_its_schema(self):
        artifact, text = pr.inspect_head(_encrypt(self.PG_DUMP), master_key=MASTER_KEY, with_text=True)
        assert artifact["kind"] == pr.KIND_PG_DUMP
        assert pr.pg_dump_schema(text) == "p_5"

    def test_plain_pg_dump_exposes_its_schema(self):
        _, text = pr.inspect_head(self.PG_DUMP, master_key=None, with_text=True)
        assert pr.pg_dump_schema(text) == "p_5"


# ---------- worker process ----------


class TestWorkerProcess:

    @needs_crypto
    def test_worker_runs_in_a_fresh_interpreter(self):
        """ The worker starts with -I and imports the utils without pylon or gevent """
        import subprocess  # pylint: disable=C0415
        worker = UTILS_PATH / "restore_worker.py"
        code = (
            "import sys, runpy; sys.argv=['w']; "
            "m = runpy.run_path({!r}, run_name='restore_worker_probe'); "
            "m['_install_stand_ins'](None); r = m['_load_utils'](); "
            "print('gevent' in sys.modules, hasattr(r, 'run_worker'))"
        ).format(str(worker))
        output = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, check=True)
        assert output.stdout.split() == ["False", "True"]
