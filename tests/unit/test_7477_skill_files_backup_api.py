"""Unit tests for #7477 - the backup and restore endpoints with skill files.

Loads api/v2/project_backup.py and api/v2/project_restore.py with flask, tools
and the database stubbed, and a fake storage client behind MinioClient.
"""
import hashlib
import importlib
import io
import json
import pathlib
import sys
import types
import zipfile

import pytest


PLUGIN_ROOT = pathlib.Path(__file__).resolve().parents[2]
PACKAGE = "_admin_7477_api"

GUIDE = b"# Guide\nRead me first.\n"
BUCKET = "skill-files"


def sha(content):
    return hashlib.sha256(content).hexdigest()


class FakeStorage:
    def __init__(self, files=None, on_download=None):
        self.files = dict(files or {})
        self.buckets = {bucket for bucket, _ in self.files}
        self.on_download = on_download

    def list_bucket(self):
        return sorted(self.buckets)

    def list_files(self, bucket):
        return [{"name": name, "size": len(data)} for (b, name), data in self.files.items() if b == bucket]

    def download_file(self, bucket, name, project_id=None):
        if self.on_download:
            self.on_download(bucket, name)
        return self.files[(bucket, name)]


class FakeCursor:
    def __init__(self, replies, executed):
        self.replies = replies
        self.executed = executed
        self._result = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        self.executed.append((sql, params))
        self._result = next((rows for marker, rows in self.replies if marker in sql), [(1,)])

    def fetchone(self):
        return self._result[0] if self._result else None

    def fetchall(self):
        return list(self._result)


class FakeConnection:
    def __init__(self, replies):
        self.replies = replies
        self.executed = []
        self.closed = False

    def cursor(self):
        return FakeCursor(self.replies, self.executed)

    def rollback(self):
        self.executed.append(("ROLLBACK", None))

    def close(self):
        self.closed = True


class Response:
    def __init__(self, stream, mimetype=None, headers=None):
        self.stream = stream
        self.mimetype = mimetype
        self.headers = headers or {}


class Envelope:
    def __init__(self, *args):
        pass

    def key_id(self, *args):
        return "key"

    def is_encrypted(self, head):
        return False

    def iter_encrypt(self, stream, key):
        return stream

    def iter_decrypt(self, stream, key):
        return stream

    def wrap_decrypt(self, opener, key):
        return opener


def _identity_decorator(*args, **kwargs):
    return lambda function: function


def _tools_stub(state):
    tools = types.ModuleType("tools")
    tools.auth = types.SimpleNamespace(
        decorators=types.SimpleNamespace(check_api=_identity_decorator),
        current_user=lambda: {"id": 1, "name": "Admin"},
        resolve_permissions=lambda **kwargs: [], has_access=lambda *args: True,
    )
    tools.api_tools = types.SimpleNamespace(APIModeHandler=object, APIBase=object)
    tools.register_openapi = _identity_decorator
    tools.context = types.SimpleNamespace(
        db=types.SimpleNamespace(engine=types.SimpleNamespace(raw_connection=lambda: state.connection)),
        rpc_manager=types.SimpleNamespace(timeout=lambda seconds: types.SimpleNamespace(
            admin_get_users_ids_in_project=lambda project_id: [1],
            projects_get_personal_project_id=lambda user_id: None,
        )),
    )
    tools.constants = types.SimpleNamespace(
        POSTGRES_SCHEMA="centry", POSTGRES_HOST="db", POSTGRES_PORT=5432,
        POSTGRES_USER="u", POSTGRES_PASSWORD="p", POSTGRES_DB="db",
    )
    tools.artifact_crypto = types.SimpleNamespace(
        ENVELOPE_SUFFIX=".enc", ENVELOPE_MIMETYPE="application/octet-stream", CIPHER="aes", KDF="hkdf",
        FRAME_SIZE=1, MAX_FRAME_SIZE=1, POLICY_DISABLED="disabled", POLICY_ENABLED="enabled",
        POLICY_REQUIRED="required", POLICIES=("disabled", "enabled", "required"), Envelope=Envelope,
        configured_master_key=lambda: None, resolve_policy=lambda config, key: "enabled",
    )
    tools.project_constants = {"PROJECT_SCHEMA_TEMPLATE": "p_{}"}
    tools.MinioClient = types.SimpleNamespace(from_project_id=lambda project_id: state.storage)
    return tools


@pytest.fixture()
def endpoints(monkeypatch):
    """ The backup and restore endpoint modules loaded against the stubs """
    state = types.SimpleNamespace(storage=FakeStorage(), connection=FakeConnection([]))
    tools = _tools_stub(state)
    logged = []
    log = types.SimpleNamespace(
        info=lambda *a, **k: logged.append(a), warning=lambda *a, **k: None,
        error=lambda *a, **k: None, exception=lambda *a, **k: None,
    )
    pylon_tools = types.ModuleType("pylon.core.tools")
    pylon_tools.log = log
    flask = types.ModuleType("flask")
    flask.Response = Response
    flask.request = types.SimpleNamespace(args={}, form={}, files={}, headers={}, host="localhost")
    for name, module in (
            ("tools", tools), ("flask", flask), ("pylon", types.ModuleType("pylon")),
            ("pylon.core", types.ModuleType("pylon.core")), ("pylon.core.tools", pylon_tools),
    ):
        monkeypatch.setitem(sys.modules, name, module)
    for name, path in (("", PLUGIN_ROOT), (".utils", PLUGIN_ROOT / "utils"),
                       (".api", PLUGIN_ROOT / "api"), (".api.v2", PLUGIN_ROOT / "api" / "v2")):
        package = types.ModuleType(PACKAGE + name)
        package.__path__ = [str(path)]
        monkeypatch.setitem(sys.modules, PACKAGE + name, package)
    for name in list(sys.modules):
        if name.startswith(PACKAGE + ".utils.") or name.startswith(PACKAGE + ".api.v2."):
            monkeypatch.delitem(sys.modules, name)
    backup = importlib.import_module(PACKAGE + ".api.v2.project_backup")
    restore = importlib.import_module(PACKAGE + ".api.v2.project_restore")
    utils = types.SimpleNamespace(
        skill_files_backup=importlib.import_module(PACKAGE + ".utils.skill_files_backup"),
        chat_backup=importlib.import_module(PACKAGE + ".utils.chat_backup"),
        project_backup=importlib.import_module(PACKAGE + ".utils.project_backup"),
    )
    return types.SimpleNamespace(
        backup=backup, restore=restore, state=state, flask=flask, utils=utils, logged=logged,
    )


def _sql_header(utils, chats_included=None, project_id=2):
    extra = {"chats_included": chats_included} if chats_included else None
    return utils.project_backup._header(  # pylint: disable=W0212
        project_id, "Private", "p_2", "2026-10-30T00:00:00+00:00", True, ["skill_version_files"], [], {}, extra,
    ) + 'INSERT INTO "skill_version_files" ("id") VALUES\n    (1)\nON CONFLICT DO NOTHING;\nCOMMIT;\n'


def _backup_connection(with_table=True, rows=None, extra=()):
    rows = [(sha(GUIDE), len(GUIDE))] if rows is None else rows
    return FakeConnection([
        ("information_schema.schemata", [(1,)]),
        ('"project" where id', [("Private",)]),
        ("information_schema.tables", [(1,)] if with_table else []),
        ("skill_version_files", rows),
        *extra,
    ])


def _download(endpoints, exclude_tables=(), user=None, **kwargs):
    endpoints.backup.iter_project_backup_sql = lambda *args, **kw: iter(
        [_sql_header(endpoints.utils, kwargs.get("include_chats"))])
    return endpoints.backup.make_backup_response(2, True, list(exclude_tables), user=user, **kwargs)


@pytest.mark.parametrize("user", [None, {"id": 1, "name": "Admin"}], ids=["admin area", "project settings"])
def test_backup_of_a_project_with_skill_files_is_a_zip_with_the_objects_before_the_sql(endpoints, user):
    endpoints.state.connection = _backup_connection()
    endpoints.state.storage = FakeStorage({(BUCKET, sha(GUIDE)): GUIDE})
    response = _download(endpoints, user=user)
    assert response.mimetype == "application/zip"
    assert response.headers["Content-Disposition"].endswith('.zip"')
    archive = zipfile.ZipFile(io.BytesIO(b"".join(response.stream)))
    assert archive.namelist() == [
        "info.json", "skill-files/" + sha(GUIDE), "skill-files-manifest.json", "backup.sql", "manifest.json",
    ]
    assert archive.read("skill-files/" + sha(GUIDE)) == GUIDE
    assert archive.read("backup.sql").startswith(b"--\n-- ELITEA project backup")
    assert json.loads(archive.read("skill-files-manifest.json"))["files"] == [
        {"sha256": sha(GUIDE), "size": len(GUIDE), "status": "ok"},
    ]
    assert json.loads(archive.read("info.json"))["skill_files_count"] == 1


@pytest.mark.parametrize("connection", [
    _backup_connection(rows=[]),
    _backup_connection(with_table=False),
], ids=["no rows", "no table"])
def test_backup_of_a_project_without_skill_files_stays_plain_sql(endpoints, connection):
    endpoints.state.connection = connection
    response = _download(endpoints)
    assert response.mimetype == "application/sql"
    assert response.headers["Content-Disposition"].endswith('.sql"')
    assert b"".join(response.stream).startswith(b"--\n-- ELITEA project backup")


def test_backup_excluding_the_manifest_table_leaves_the_objects_out(endpoints):
    endpoints.state.connection = _backup_connection()
    endpoints.state.storage = FakeStorage({(BUCKET, sha(GUIDE)): GUIDE})
    assert _download(endpoints, exclude_tables=[" skill_version_files"]).mimetype == "application/sql"


def test_backup_reads_its_hash_list_in_a_repeatable_read_snapshot_holding_the_skill_file_lock(endpoints):
    connection = _backup_connection()
    endpoints.state.connection = connection
    endpoints.state.storage = FakeStorage({(BUCKET, sha(GUIDE)): GUIDE})
    b"".join(_download(endpoints).stream)
    statements = [sql for sql, _ in connection.executed]
    snapshot = statements.index("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
    assert statements[snapshot - 1] == "ROLLBACK"
    assert connection.executed[snapshot + 1] == (endpoints.utils.skill_files_backup.SKILL_FILE_WRITE_LOCK, (2,))
    hashes = next(index for index, sql in enumerate(statements) if "group by sha256" in sql)
    assert hashes > snapshot + 1
    assert "ROLLBACK" not in statements[snapshot:hashes]


def test_backup_ends_its_snapshot_with_the_sql_before_any_attachment_is_read(endpoints):
    connection = _backup_connection(extra=(
        ("count(*)", [(1,)]),
        ("chat_messages_attachment", [("attachments", "photo.png")]),
    ))
    endpoints.state.connection = connection
    reads = []
    endpoints.state.storage = FakeStorage(
        {(BUCKET, sha(GUIDE)): GUIDE, ("attachments", "photo.png"): b"PNG"},
        on_download=lambda bucket, name: reads.append((bucket, connection.closed)),
    )
    response = _download(endpoints, include_chats="with_attachments", user={"id": 1, "name": "Admin"})
    archive = zipfile.ZipFile(io.BytesIO(b"".join(response.stream)))
    assert archive.read("attachments/attachments/photo.png") == b"PNG"
    assert reads == [(BUCKET, False), ("attachments", True)]


def test_backup_with_chats_but_without_attachments_carries_the_skill_files_and_no_attachment(endpoints):
    endpoints.state.connection = _backup_connection(extra=(
        ("count(*)", [(1,)]),
        ("chat_messages_attachment", [("attachments", "photo.png")]),
    ))
    endpoints.state.storage = FakeStorage({(BUCKET, sha(GUIDE)): GUIDE, ("attachments", "photo.png"): b"PNG"})
    response = _download(endpoints, include_chats="without_attachments", user={"id": 1, "name": "Admin"})
    assert response.mimetype == "application/zip"
    archive = zipfile.ZipFile(io.BytesIO(b"".join(response.stream)))
    assert sorted(archive.namelist()) == sorted([
        "info.json", "backup.sql", "skill-files/" + sha(GUIDE), "skill-files-manifest.json", "manifest.json",
    ])
    assert json.loads(archive.read("info.json"))["chats_included"] == "without_attachments"


def test_backup_without_skill_files_leaves_the_objects_out_and_never_reads_them(endpoints):
    connection = _backup_connection()
    endpoints.state.connection = connection
    endpoints.state.storage = FakeStorage({(BUCKET, sha(GUIDE)): GUIDE})
    response = _download(endpoints, include_skill_files=False)
    assert response.mimetype == "application/sql"
    assert b"".join(response.stream).startswith(b"--\n-- ELITEA project backup")
    assert not any("group by sha256" in sql for sql, _ in connection.executed)


@pytest.mark.parametrize("handler", ["AdminAPI", "PromptLibAPI"])
@pytest.mark.parametrize("value, include", [
    (None, True), ("all", True), (" ALL ", True), ("none", False),
], ids=["default", "all", "case and spaces", "none"])
def test_both_backup_endpoints_read_the_skill_files_option(endpoints, monkeypatch, handler, value, include):
    captured = {}
    monkeypatch.setattr(endpoints.backup, "make_backup_response", lambda *args, **kwargs: captured.update(kwargs))
    endpoints.flask.request.args = {} if value is None else {"include_skill_files": value}
    getattr(endpoints.backup, handler)().get(2)
    assert captured["include_skill_files"] is include


@pytest.mark.parametrize("handler", ["AdminAPI", "PromptLibAPI"])
def test_an_unknown_skill_files_option_is_refused(endpoints, monkeypatch, handler):
    monkeypatch.setattr(endpoints.backup, "make_backup_response", lambda *args, **kwargs: pytest.fail("ran"))
    endpoints.flask.request.args = {"include_skill_files": "some"}
    assert getattr(endpoints.backup, handler)().get(2) == (
        {"ok": False, "error": "unknown include_skill_files option"}, 400,
    )


@pytest.mark.parametrize("with_table, expected", [
    (True, {"skill_files_count": 1, "skill_files_size": len(GUIDE)}),
    (False, {"skill_files_count": 0, "skill_files_size": 0}),
], ids=["with skill files", "without the table"])
def test_the_backup_summary_counts_the_skill_files(endpoints, with_table, expected):
    endpoints.state.connection = _backup_connection(with_table=with_table, extra=(("count(*)", [(0,)]),))
    endpoints.state.connection.replies.insert(0, ("chat_messages_attachment", []))
    body, status = endpoints.backup.make_chat_summary(2, {"id": 1})
    assert status == 200
    assert {key: body[key] for key in expected} == expected


def _skill_zip(utils, chats_included=None, project_id=2):
    skill_files = [{"sha256": sha(GUIDE), "size": len(GUIDE)}]
    info = utils.chat_backup.make_info(project_id, "Private", {}, chats_included or "none",
                                       {"chats_count": 0, "attachments": []}, skill_files)
    return b"".join(utils.chat_backup.iter_backup_zip(
        info, iter([_sql_header(utils, chats_included, project_id).encode("utf-8")]), [], None, skill_files,
        lambda key: GUIDE,
    ))


class FakeJobStore:
    """ The job row a restore request creates, kept in memory """

    def __init__(self):
        self.jobs = {}

    def active(self, project_id):
        return None

    def create(self, project_id, user_id, mode, options, artifact, instance):
        job = {"id": "job-1", "project_id": project_id, "user_id": user_id, "mode": mode,
               "options": options, "artifact": artifact, "instance": instance}
        self.jobs[job["id"]] = job
        return job

    def attach_task(self, job_id, task_id):
        pass

    def fail(self, job_id, *args, **kwargs):
        raise AssertionError("the restore request failed its job: {}".format(args))


class FakeWorkers:
    """ Takes the worker start: the test runs the worker side itself """

    def __init__(self):
        self.started = []

    def busy(self):
        return False

    def start(self, job_id, payload, on_exit, open_storage=None):
        self.started.append(dict(payload, open_storage=open_storage))
        return 1


def _upload(endpoints, data, result=None, **form):
    """ A restore end to end: the request starts the job, then the worker applies it

    Returns the body and status the job ends with - the response of a restore
    that waits for its job - and the arguments restore_safe_backup got.
    """
    captured = {}

    def restore_safe_backup(connection, **kwargs):
        captured.update(kwargs)
        return dict(result or {})
    runner = endpoints.restore.restore_runner
    runner.restore_safe_backup = restore_safe_backup
    endpoints.state.connection = FakeConnection([("information_schema.schemata", [(1,)])])
    # The job is followed by the caller; the request answers 202 right away
    endpoints.flask.request.form = dict({"background": "true"}, **form)
    endpoints.flask.request.files = {"file": types.SimpleNamespace(filename="backup.zip", stream=io.BytesIO(data))}
    #
    store, workers = FakeJobStore(), FakeWorkers()
    spool_dir = runner.spool_dir({})
    module = types.SimpleNamespace(
        restore_job_store=lambda: store, restore_workers=workers, restore_job_schema="centry",
        restore_settings={"spool_dir": spool_dir, "max_archive_bytes": 10 ** 9, "lock_timeout": "30s"},
        restore_worker_database=lambda: {},
    )
    body, status = endpoints.restore.apply_uploaded_backup(module, 2)
    if status != 202:
        return body, status, captured
    #
    payload = workers.started[0]
    # The worker's storage calls are served on the platform client the request hands over
    storage = payload["open_storage"]() if payload["with_storage"] else None
    try:
        body = runner.apply_job(
            endpoints.state.connection, store.jobs[payload["job_id"]], payload["spool_path"], None,
            storage, max_archive_bytes=10 ** 9, lock_timeout="30s",
        )
    finally:
        runner.remove_spool(payload["spool_path"])
    return body, 200, captured


def test_restore_of_a_zip_hands_the_archive_to_the_skill_file_restorer(endpoints):
    endpoints.state.storage = FakeStorage()
    body, status, captured = _upload(endpoints, _skill_zip(endpoints.utils))
    assert status == 200
    assert body["artifact"]["skill_files_count"] == 1
    handler = captured["skill_file_handler"]
    assert isinstance(handler, endpoints.utils.skill_files_backup.SkillFileRestorer)
    assert handler.members == {"skill-files/" + sha(GUIDE)}
    assert handler.open_client() is endpoints.state.storage


def test_restore_of_plain_sql_still_checks_the_skill_files(endpoints):
    body, status, captured = _upload(endpoints, _sql_header(endpoints.utils).encode("utf-8"))
    assert status == 200
    handler = captured["skill_file_handler"]
    assert isinstance(handler, endpoints.utils.skill_files_backup.SkillFileRestorer)
    assert handler.archive is None
    assert body["artifact"]["skill_files_count"] == 0


@pytest.mark.parametrize("source_project", [2, 5], ids=["same project", "another project"])
def test_restore_locks_the_skill_files_of_the_target_project(endpoints, source_project):
    body, status, captured = _upload(
        endpoints, _skill_zip(endpoints.utils, project_id=source_project), allow_project_mismatch="true",
    )
    assert status == 200
    assert captured["project_id"] == 2


def test_the_restore_log_line_carries_the_skill_file_counts_without_paths(endpoints):
    result = {"skill_files": {"total": 2, "present": 0, "uploaded": 1, "missing": 1,
                              "missing_paths": ["config/prod-notes.md"], "unchecked": False}}
    body, status, _ = _upload(endpoints, _skill_zip(endpoints.utils), result=result)
    assert status == 200
    assert body["result"]["skill_files"]["missing_paths"] == ["config/prod-notes.md"]
    applied = [args for args in endpoints.logged if args and "project_restore_applied" in str(args[0])]
    assert applied and "config/prod-notes.md" not in repr(applied)
    assert {"total": 2, "present": 0, "uploaded": 1, "missing": 1, "unchecked": False} in applied[0]


def test_skill_files_zip_with_chats_but_no_attachment_files_only_relinks_attachments(endpoints):
    body, status, captured = _upload(
        endpoints, _skill_zip(endpoints.utils, "without_attachments"), restore_chats="with_attachments",
    )
    assert status == 200
    assert body["artifact"]["has_attachment_files"] is False
    assert captured["restore_chats"] == "without_attachments"


def _request(endpoints, data, **form):
    """ The restore request alone, against an in-memory job store and worker pool """
    endpoints.state.connection = FakeConnection([("information_schema.schemata", [(1,)])])
    endpoints.flask.request.form = dict(form)
    endpoints.flask.request.files = {"file": types.SimpleNamespace(filename="backup.sql", stream=io.BytesIO(data))}
    store, workers = FakeJobStore(), FakeWorkers()
    runner = endpoints.restore.restore_runner
    module = types.SimpleNamespace(
        restore_job_store=lambda: store, restore_workers=workers, restore_job_schema="centry",
        restore_settings={"spool_dir": runner.spool_dir({}), "max_archive_bytes": 10 ** 9, "lock_timeout": "30s"},
        restore_worker_database=lambda: {},
    )
    return endpoints.restore.apply_uploaded_backup(module, 2), store, workers


def test_a_client_that_does_not_ask_for_a_job_waits_for_the_result(endpoints, monkeypatch):
    """ An older UI or a script keeps the synchronous answer it always got """
    waited = []
    monkeypatch.setattr(endpoints.restore, "_wait_for_job", lambda store, job_id: (
        waited.append(job_id) or ({"ok": True, "result": {"total_rows": 1}}, 200)))
    (body, status), _, workers = _request(endpoints, _sql_header(endpoints.utils).encode("utf-8"))
    assert status == 200
    assert body == {"ok": True, "result": {"total_rows": 1}}
    assert waited == ["job-1"]
    endpoints.restore.restore_runner.remove_spool(workers.started[0]["spool_path"])


def test_background_answers_202_with_the_job(endpoints):
    (body, status), _, workers = _request(endpoints, _sql_header(endpoints.utils).encode("utf-8"), background="true")
    assert status == 202
    assert body["job_id"] == "job-1" and body["status"] == "running"
    endpoints.restore.restore_runner.remove_spool(workers.started[0]["spool_path"])


@pytest.mark.parametrize("form, expected", [
    ({"size": "123456789"}, 123456789),
    ({}, None),
], ids=["slice with its real size", "whole file without size"])
def test_inspect_reports_the_size_of_the_whole_file(endpoints, form, expected):
    data = _sql_header(endpoints.utils).encode("utf-8") + b"-- padding\n" * 200000
    (body, status), _, workers = _request(endpoints, data, inspect="true", **form)
    assert status == 200 and body["inspect"] is True
    assert body["artifact"]["size"] == (expected if expected is not None else len(data))
    assert workers.started == []


def test_a_busy_pod_refuses_before_writing_the_upload_to_disk(endpoints, monkeypatch):
    spooled = []
    monkeypatch.setattr(endpoints.restore.restore_runner, "spool_upload",
                        lambda *args, **kwargs: spooled.append(1) or ("/nowhere", 0))
    endpoints.state.connection = FakeConnection([("information_schema.schemata", [(1,)])])
    endpoints.flask.request.form = {"background": "true"}
    endpoints.flask.request.files = {"file": types.SimpleNamespace(
        filename="backup.sql", stream=io.BytesIO(_sql_header(endpoints.utils).encode("utf-8")))}
    store = FakeJobStore()
    module = types.SimpleNamespace(
        restore_job_store=lambda: store, restore_workers=types.SimpleNamespace(busy=lambda: True),
        restore_job_schema="centry", restore_settings={}, restore_worker_database=lambda: {},
    )
    body, status = endpoints.restore.apply_uploaded_backup(module, 2)
    assert status == 503 and body["error"] == "restore_capacity_busy"
    assert spooled == [] and store.jobs == {}

