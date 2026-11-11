"""Unit tests for #7477 - project backup and restore of the skill file objects.

Covers utils/skill_files_backup.py and the skill-file parts of utils/chat_backup.py
against a fake storage client holding one 'skill-files' bucket keyed by sha256.
"""
import hashlib
import importlib.util
import io
import json
import pathlib
import sys
import types
import zipfile

import pytest


UTILS_PATH = pathlib.Path(__file__).resolve().parents[2] / "utils"
PACKAGE = "_admin_utils_7477"


def _load_utils():
    """Import the backup / restore utils without a running pylon"""
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
    package = types.ModuleType(PACKAGE)
    package.__path__ = [str(UTILS_PATH)]
    sys.modules[PACKAGE] = package
    #
    modules = {}
    for name in ("skill_files_backup", "chat_backup", "chat_restore", "project_backup", "project_restore"):
        spec = importlib.util.spec_from_file_location(
            "{}.{}".format(PACKAGE, name), UTILS_PATH / "{}.py".format(name),
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        modules[name] = module
    return modules


MODULES = _load_utils()
sfb = MODULES["skill_files_backup"]
cb = MODULES["chat_backup"]
cr = MODULES["chat_restore"]
pr = MODULES["project_restore"]

BUCKET = "skill-files"

GUIDE = b"# Guide\nRead me first.\n"
LOGO = bytes(range(256)) * 4
GONE = b"deleted from storage behind the rows' back"


def sha(content):
    return hashlib.sha256(content).hexdigest()


class FakeCursor:
    """ Answers every query with ``rows``, and the table check with whether the table exists """

    def __init__(self, table_exists=True, rows=()):
        self.table_exists = table_exists
        self.rows = list(rows)
        self.executed = []
        self._result = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        self.executed.append((sql, params))
        if "information_schema.tables" in sql:
            self._result = [(1,)] if self.table_exists else []
        else:
            self._result = list(self.rows)

    def fetchone(self):
        return self._result[0] if self._result else None

    def fetchall(self):
        return list(self._result)


class FakeStorage:
    """ A project's buckets; files maps (bucket, key) -> bytes """

    def __init__(self, files=None, fail=()):
        self.files = dict(files or {})
        self.buckets = {bucket for bucket, _ in self.files}
        self.fail = set(fail)
        self.created = []
        self.uploads = []
        self.removed = []

    def list_bucket(self):
        return sorted(self.buckets)

    def create_bucket(self, bucket, bucket_type=None, retention_days=None):
        self.created.append({"bucket": bucket, "bucket_type": bucket_type, "retention_days": retention_days})
        self.buckets.add(bucket)

    def list_files(self, bucket):
        if bucket not in self.buckets or "list" in self.fail:
            raise RuntimeError("NoSuchBucket" if bucket not in self.buckets else "storage is down")
        return [{"name": name, "size": len(data)} for (b, name), data in self.files.items() if b == bucket]

    def upload_file(self, bucket, content, name):
        if name in self.fail:
            raise RuntimeError("storage is down")
        self.uploads.append((bucket, name))
        self.files[(bucket, name)] = content

    def download_file(self, bucket, name, project_id=None):
        return self.files[(bucket, name)]

    def remove_file(self, bucket, name):
        self.removed.append((bucket, name))
        self.files.pop((bucket, name), None)


def _rows():
    """ skill_version_files rows (sha256, size, path): the guide in two versions, the logo once, a hash
        storage lost """
    return [
        (sha(GUIDE), len(GUIDE), "references/guide.md"),
        (sha(GUIDE), len(GUIDE), "v2/references/guide.md"),
        (sha(LOGO), len(LOGO), "assets/logo.bin"),
        (sha(GONE), len(GONE), "notes.txt"),
    ]


def _distinct():
    """ What the backup's grouped hash query answers for _rows() """
    return sorted({(row[0], row[1]) for row in _rows()})


def _source_storage():
    return FakeStorage({(BUCKET, sha(GUIDE)): GUIDE, (BUCKET, sha(LOGO)): LOGO})


def _skill_files():
    return sfb.resolve_skill_files(FakeCursor(rows=_distinct()), "p_2")


def _build_zip(skill_files=None, storage=None, attachments=(), sql=b"-- ELITEA project backup\n"):
    storage = storage or _source_storage()
    skill_files = _skill_files() if skill_files is None else skill_files
    info = cb.make_info(2, "Private", {"id": 1, "name": "Admin"}, cb.CHATS_NONE,
                        {"chats_count": 0, "attachments": list(attachments)}, skill_files)
    data = b"".join(cb.iter_backup_zip(
        info, iter([sql]), list(attachments),
        lambda bucket, name: b"", skill_files,
        lambda key: storage.download_file(BUCKET, key),
    ))
    return info, data


def _open(data):
    archive, _, _ = cr.open_backup_zip(io.BytesIO(data), 10 ** 9)
    return archive


def _rewrite_zip(data, change):
    """ The archive with each member passed through change(name, bytes); None drops the member """
    buffer = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(data)) as source, zipfile.ZipFile(buffer, "w") as target:
        for item in source.infolist():
            content = change(item.filename, source.read(item.filename))
            if content is not None:
                target.writestr(item, content)
    return buffer.getvalue()


# ---------- snapshot ----------

class RecordingConnection:
    def __init__(self):
        self.calls = []

    def rollback(self):
        self.calls.append("rollback")

    def cursor(self):
        connection = self

        class Cursor(FakeCursor):
            def execute(self, sql, params=None):
                connection.calls.append((sql, params))

        return Cursor()


def test_the_backup_snapshot_starts_a_repeatable_read_transaction_holding_the_skill_file_lock():
    connection = RecordingConnection()
    sfb.begin_backup_snapshot(connection, 7)
    assert connection.calls == [
        "rollback",
        ("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ", None),
        ("SELECT pg_advisory_xact_lock_shared(hashtext('skill-files'), %s)", (7,)),
    ]


# ---------- resolve ----------

def test_resolve_lists_every_distinct_hash_once_with_its_size():
    assert _skill_files() == [{"sha256": sha256, "size": size} for sha256, size in _distinct()]


def test_resolve_groups_the_project_schema_table_by_hash():
    cursor = FakeCursor(rows=_distinct())
    sfb.resolve_skill_files(cursor, "p_2")
    assert cursor.executed[-1][0] == (
        'select sha256, min(size) from "p_2"."skill_version_files" group by sha256 order by sha256'
    )


def test_resolve_without_the_table_is_empty():
    cursor = FakeCursor(table_exists=False, rows=_distinct())
    assert sfb.resolve_skill_files(cursor, "p_2") == []
    assert len(cursor.executed) == 1


# ---------- backup archive ----------

def test_archive_stores_every_object_under_its_hash_uncompressed():
    _, data = _build_zip()
    archive = zipfile.ZipFile(io.BytesIO(data))
    assert archive.read("skill-files/" + sha(GUIDE)) == GUIDE
    assert archive.read("skill-files/" + sha(LOGO)) == LOGO
    for name in ("skill-files/" + sha(GUIDE), "skill-files/" + sha(LOGO)):
        assert archive.getinfo(name).compress_type == zipfile.ZIP_STORED


def test_archive_puts_the_skill_files_between_info_and_the_sql():
    attachment = {"bucket": "attachments", "name": "c1/a.txt", "size": 1, "status": "ok"}
    _, data = _build_zip(attachments=[attachment])
    names = zipfile.ZipFile(io.BytesIO(data)).namelist()
    assert names == [
        cb.ZIP_INFO_NAME,
        *sorted("skill-files/" + sha(content) for content in (GUIDE, LOGO)),
        sfb.ZIP_SKILL_FILES_MANIFEST_NAME,
        cb.ZIP_SQL_NAME,
        "attachments/attachments/c1/a.txt",
        cb.ZIP_MANIFEST_NAME,
    ]


def test_every_skill_file_is_read_before_the_sql_is():
    events = []
    storage = _source_storage()
    skill_files = _skill_files()
    info = cb.make_info(2, "Private", {}, cb.CHATS_NONE, {"chats_count": 0, "attachments": []}, skill_files)

    def sql_chunks():
        events.append("sql")
        yield b"--"

    def read_skill_file(key):
        events.append("skill file")
        return storage.download_file(BUCKET, key)

    b"".join(cb.iter_backup_zip(info, sql_chunks(), [], None, skill_files, read_skill_file))
    assert events == ["skill file"] * len(skill_files) + ["sql"]


def test_skill_files_manifest_lists_hash_size_and_status():
    _, data = _build_zip()
    manifest = json.loads(zipfile.ZipFile(io.BytesIO(data)).read(sfb.ZIP_SKILL_FILES_MANIFEST_NAME))
    assert manifest["bucket"] == BUCKET
    assert manifest["files_count"] == 3
    assert manifest["missing_files"] == 1
    files = {item["sha256"]: item for item in manifest["files"]}
    assert files[sha(LOGO)] == {"sha256": sha(LOGO), "size": len(LOGO), "status": "ok"}
    assert files[sha(GONE)] == {"sha256": sha(GONE), "size": len(GONE), "status": "missing"}


def test_object_whose_content_no_longer_matches_its_key_is_left_out():
    storage = _source_storage()
    storage.files[(BUCKET, sha(LOGO))] = b"overwritten"
    _, data = _build_zip(storage=storage)
    archive = zipfile.ZipFile(io.BytesIO(data))
    assert "skill-files/" + sha(LOGO) not in archive.namelist()
    manifest = json.loads(archive.read(sfb.ZIP_SKILL_FILES_MANIFEST_NAME))
    assert {item["sha256"]: item["status"] for item in manifest["files"]}[sha(LOGO)] == "missing"


def test_an_unreadable_object_is_recorded_missing_and_the_backup_completes():
    _, data = _build_zip()
    archive = zipfile.ZipFile(io.BytesIO(data))
    assert "skill-files/" + sha(GONE) not in archive.namelist()
    assert archive.read(cb.ZIP_SQL_NAME) == b"-- ELITEA project backup\n"


def test_info_counts_the_skill_files():
    info, data = _build_zip()
    assert info["skill_files_count"] == 3
    assert info["skill_files_size"] == len(GUIDE) + len(LOGO) + len(GONE)
    assert cb.read_zip_info(data[:4096]) == info


def test_archive_without_skill_files_has_no_skill_entries():
    info, data = _build_zip(skill_files=[])
    names = zipfile.ZipFile(io.BytesIO(data)).namelist()
    assert names == [cb.ZIP_INFO_NAME, cb.ZIP_SQL_NAME, cb.ZIP_MANIFEST_NAME]
    assert "skill_files_count" not in info


def test_backup_archive_passes_the_restore_checks():
    _, data = _build_zip()
    archive = _open(data)
    assert sfb.read_skill_files_manifest(archive)["files_count"] == 3


def test_manifest_reader_without_skill_files_is_empty():
    _, data = _build_zip(skill_files=[])
    assert sfb.read_skill_files_manifest(_open(data)) == {}
    assert sfb.read_skill_files_manifest(None) == {}


# ---------- restore ----------

def _restorer(storage, data=None, archive=True):
    return sfb.SkillFileRestorer(lambda: storage, _open(data or _build_zip()[1]) if archive else None)


def _target_cursor(rows=None):
    return FakeCursor(rows=sorted(_rows() if rows is None else rows))


def test_restore_into_a_project_without_the_bucket_creates_it_and_uploads_every_archived_hash():
    storage = FakeStorage()
    summary = _restorer(storage)(_target_cursor(), dry_run=False)
    assert storage.created == [{"bucket": BUCKET, "bucket_type": "system", "retention_days": None}]
    assert storage.files == {(BUCKET, sha(GUIDE)): GUIDE, (BUCKET, sha(LOGO)): LOGO}
    assert summary == {
        "total": 3, "present": 0, "uploaded": 2, "missing": 1, "missing_paths": ["notes.txt"],
        "unchecked": False,
    }


def test_restore_uploads_only_the_hashes_the_target_bucket_holds_at_another_size_or_not_at_all():
    storage = FakeStorage({(BUCKET, sha(GUIDE)): GUIDE, (BUCKET, sha(LOGO)): LOGO[:10]})
    summary = _restorer(storage)(_target_cursor(), dry_run=False)
    assert storage.uploads == [(BUCKET, sha(LOGO))]
    assert storage.files[(BUCKET, sha(LOGO))] == LOGO
    assert storage.created == []
    assert (summary["present"], summary["uploaded"]) == (1, 1)


def test_restore_into_the_source_project_uploads_nothing():
    storage = FakeStorage({(BUCKET, sha(GUIDE)): GUIDE, (BUCKET, sha(LOGO)): LOGO})
    summary = _restorer(storage)(_target_cursor([row for row in _rows() if row[0] != sha(GONE)]), dry_run=False)
    assert storage.uploads == []
    assert (summary["present"], summary["uploaded"], summary["missing"]) == (2, 0, 0)


def test_restore_reads_every_row_of_the_target_table():
    cursor = _target_cursor()
    _restorer(FakeStorage())(cursor, dry_run=False)
    assert cursor.executed == [('SELECT sha256, size, path FROM "skill_version_files" ORDER BY sha256, path', None)]


def test_restore_without_rows_does_not_open_storage():
    opened = []
    restorer = sfb.SkillFileRestorer(lambda: opened.append(1), _open(_build_zip()[1]))
    summary = restorer(FakeCursor(rows=[]), dry_run=False)
    assert summary["total"] == 0
    assert opened == []


def test_dry_run_reports_the_uploads_without_making_them():
    storage = FakeStorage()
    summary = _restorer(storage)(_target_cursor(), dry_run=True)
    assert summary["uploaded"] == 2
    assert storage.files == {} and storage.created == []


def test_upload_failure_fails_the_restore_and_leaves_earlier_uploads_to_the_sweep():
    first, second = sorted((sha(GUIDE), sha(LOGO)))
    storage = FakeStorage(fail={second})
    with pytest.raises(RuntimeError, match="storage is down"):
        _restorer(storage)(_target_cursor(), dry_run=False)
    assert list(storage.files) == [(BUCKET, first)]
    assert storage.removed == []


def test_archived_content_that_does_not_match_its_hash_is_not_uploaded():
    data = _rewrite_zip(_build_zip()[1], lambda name, content: b"tampered" if name == "skill-files/" + sha(LOGO)
                        else content)
    storage = FakeStorage()
    summary = _restorer(storage, data)(_target_cursor(), dry_run=False)
    assert (BUCKET, sha(LOGO)) not in storage.files
    assert summary["missing_paths"] == ["assets/logo.bin", "notes.txt"]


def test_a_hash_without_its_member_counts_as_missing_with_every_path_listing_it():
    data = _rewrite_zip(_build_zip()[1], lambda name, content: None if name == "skill-files/" + sha(GUIDE)
                        else content)
    storage = FakeStorage()
    summary = _restorer(storage, data)(_target_cursor(), dry_run=False)
    assert summary["missing_paths"] == ["notes.txt", "references/guide.md", "v2/references/guide.md"]
    assert summary["missing"] == 2
    assert storage.files == {(BUCKET, sha(LOGO)): LOGO}


def test_restore_without_an_archive_reports_every_absent_hash_missing():
    storage = FakeStorage({(BUCKET, sha(GUIDE)): GUIDE})
    summary = _restorer(storage, archive=False)(_target_cursor(), dry_run=False)
    assert (summary["present"], summary["uploaded"], summary["missing"]) == (1, 0, 2)
    assert summary["missing_paths"] == ["assets/logo.bin", "notes.txt"]
    assert storage.uploads == []


def test_the_restore_reports_at_most_fifty_missing_paths_but_counts_every_hash():
    rows = [("{:064x}".format(index), 1, "file-{:02d}.md".format(index)) for index in range(60)]
    summary = _restorer(FakeStorage(), archive=False)(FakeCursor(rows=rows), dry_run=False)
    assert summary["missing"] == 60
    assert summary["missing_paths"] == [row[2] for row in rows[:50]]


def test_a_listing_error_without_skill_files_in_the_backup_leaves_the_files_unchecked():
    storage = FakeStorage({(BUCKET, sha(GUIDE)): GUIDE}, fail={"list"})
    summary = _restorer(storage, archive=False)(_target_cursor(), dry_run=False)
    assert summary["unchecked"] is True
    assert (summary["present"], summary["uploaded"], summary["missing"]) == (0, 0, 0)


def test_a_listing_error_with_skill_files_in_the_backup_fails_the_restore():
    storage = FakeStorage({(BUCKET, sha(GUIDE)): GUIDE}, fail={"list"})
    with pytest.raises(RuntimeError, match="storage is down"):
        _restorer(storage)(_target_cursor(), dry_run=False)


def test_the_restore_log_gets_the_counts_without_the_paths():
    summary = {"total": 3, "present": 1, "uploaded": 1, "missing": 1, "missing_paths": ["x"], "unchecked": False}
    assert sfb.restore_summary_counts(summary) == {
        "total": 3, "present": 1, "uploaded": 1, "missing": 1, "unchecked": False,
    }
    assert sfb.restore_summary_counts(None) == {}


class FakeRestoreCursor:
    """ Answers the catalog queries restore_safe_backup makes for a target schema holding ``tables`` """

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
        self.connection.executed.append((sql, params))
        lowered = sql.lower()
        self.rowcount = 1 if lowered.startswith("insert") else 0
        tables = self.connection.tables
        if "from information_schema.tables" in lowered:
            self._result = [(table,) for table in tables]
        elif "from information_schema.columns" in lowered and "is_nullable" not in lowered:
            self._result = [(table, column) for table, columns in tables.items() for column in columns]
        else:
            self._result = []

    def fetchall(self):
        return self._result


class FakeRestoreConnection:
    def __init__(self, tables):
        self.tables = tables
        self.executed = []

    def cursor(self):
        return FakeRestoreCursor(self)

    def commit(self):
        pass

    def rollback(self):
        pass


TARGET_TABLES = {
    "applications": {"id", "name"},
    "skill_version_files": {"id", "sha256"},
}

APPLICATION_ROWS = 'INSERT INTO "applications" ("id", "name") VALUES\n    (5, \'Agent\')\nON CONFLICT DO NOTHING;\n'
SKILL_FILE_ROWS = (
    'INSERT INTO "skill_version_files" ("id", "sha256") VALUES\n    (1, \'abc\')\nON CONFLICT DO NOTHING;\n'
)


def _backup(*statements):
    return 'SET search_path TO "p_2", public;\nBEGIN;\n' + "".join(statements) + "COMMIT;\n"


@pytest.mark.parametrize("statements, handled", [
    ((APPLICATION_ROWS, SKILL_FILE_ROWS), True),
    ((APPLICATION_ROWS,), False),
], ids=["restore writes skill file rows", "restore writes none"])
def test_the_skill_file_restorer_runs_only_when_the_restore_writes_skill_file_rows(statements, handled):
    calls = []
    summary = pr.restore_safe_backup(
        FakeRestoreConnection(TARGET_TABLES), lambda: iter([_backup(*statements)]), "p_3",
        skill_file_handler=lambda cursor, dry_run: calls.append(dry_run) or {"total": 0},
    )
    assert calls == ([False] if handled else [])
    assert ("skill_files" in summary) is handled


def test_the_restore_takes_the_skill_file_lock_of_the_target_before_it_truncates():
    connection = FakeRestoreConnection(TARGET_TABLES)
    pr.restore_safe_backup(
        connection, lambda: iter([_backup(SKILL_FILE_ROWS)]), "p_3", truncate=True, project_id=3,
    )
    statements = [sql for sql, _ in connection.executed]
    lock = statements.index(sfb.SKILL_FILE_WRITE_LOCK)
    assert connection.executed[lock][1] == (3,)
    assert statements[lock - 1].startswith("SET LOCAL search_path")
    assert lock < next(index for index, sql in enumerate(statements) if sql.startswith("TRUNCATE"))


def test_a_restore_failing_after_the_uploads_leaves_them_to_the_sweep(monkeypatch):
    storage = FakeStorage()
    handler = sfb.SkillFileRestorer(lambda: storage, _open(_build_zip()[1]))
    original = FakeRestoreCursor.execute

    def execute(self, sql, params=None):
        original(self, sql, params)
        if sql.startswith("SELECT sha256, size, path"):
            self._result = sorted(_rows())

    def explode(*args, **kwargs):
        raise RuntimeError("late failure")
    monkeypatch.setattr(FakeRestoreCursor, "execute", execute)
    monkeypatch.setattr(pr, "_remap_project_reference_columns", explode)
    with pytest.raises(RuntimeError, match="late failure"):
        pr.restore_safe_backup(
            FakeRestoreConnection(TARGET_TABLES), lambda: iter([_backup(SKILL_FILE_ROWS)]), "p_3",
            member_user_ids=[1], skill_file_handler=handler, project_id=3,
        )
    assert set(storage.files) == {(BUCKET, sha(GUIDE)), (BUCKET, sha(LOGO))}
    assert storage.removed == []
