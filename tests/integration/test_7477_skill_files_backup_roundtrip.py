"""Integration tests for #7477 - backup and restore of skill files against PostgreSQL.

A throwaway database is created next to the one in ELITEA_TEST_PG_DSN (the
user needs CREATEDB) and dropped afterwards. The source project's skill
versions reference objects of its 'skill-files' bucket by sha256; the backup
ZIP is restored into a second project with its own fake bucket.

    ELITEA_TEST_PG_DSN="postgresql://centry:changeme@localhost:5432/db" \\
        python tests/run_tests.py integration/test_7477_skill_files_backup_roundtrip.py

Skipped when the variable is not set.
"""
import hashlib
import importlib.util
import io
import os
import pathlib
import sys
import threading
import time
import types
import uuid

import pytest

psycopg2 = pytest.importorskip("psycopg2")
from psycopg2 import sql as psql  # noqa: E402  pylint: disable=C0413


DSN = os.environ.get("ELITEA_TEST_PG_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="ELITEA_TEST_PG_DSN is not set")

UTILS_PATH = pathlib.Path(__file__).resolve().parents[2] / "utils"
PACKAGE = "_admin_utils_7477_it"

SOURCE = "p_911"
TARGET = "p_912"
SOURCE_ID = 911
TARGET_ID = 912
RESTORER = 6
BUCKET = "skill-files"

GUIDE = b"# Guide\nRead me first.\n"
LOGO = bytes(range(256)) * 8

# Skill tables as elitea_core creates them (models/skill.py), with the #7185 manifest table
LOCK_KEY = "hashtext('skill-files')"
DDL = """
CREATE TABLE {s}.skills (id serial PRIMARY KEY, name varchar NOT NULL, description varchar NOT NULL,
    owner_id integer NOT NULL, author_id integer NOT NULL, created_at timestamp NOT NULL DEFAULT now(),
    uuid uuid NOT NULL, meta jsonb NOT NULL DEFAULT '{{}}', shared_owner_id integer, shared_id integer);
CREATE TABLE {s}.skill_versions (id serial PRIMARY KEY,
    skill_id integer NOT NULL REFERENCES {s}.skills(id) ON DELETE CASCADE,
    name varchar NOT NULL, instructions text NOT NULL, author_id integer NOT NULL,
    created_at timestamp NOT NULL DEFAULT now(), uuid uuid NOT NULL, meta jsonb NOT NULL DEFAULT '{{}}',
    status varchar NOT NULL, run_settings jsonb);
CREATE TABLE {s}.skill_version_files (id serial PRIMARY KEY,
    skill_version_id integer NOT NULL REFERENCES {s}.skill_versions(id) ON DELETE CASCADE,
    path varchar(1024) NOT NULL, size integer NOT NULL, sha256 varchar(64) NOT NULL,
    content_type varchar(255) NOT NULL, is_text boolean NOT NULL, created_at timestamp NOT NULL DEFAULT now());
CREATE UNIQUE INDEX ON {s}.skill_version_files (skill_version_id, lower(path));
CREATE INDEX ON {s}.skill_version_files (sha256);
"""


def _load_utils():
    if "pylon.core.tools" not in sys.modules:
        tools = types.ModuleType("pylon.core.tools")
        tools.log = types.SimpleNamespace(
            info=lambda *a, **k: None, warning=lambda *a, **k: None,
            error=lambda *a, **k: None, exception=lambda *a, **k: None,
        )
        sys.modules.setdefault("pylon", types.ModuleType("pylon"))
        sys.modules.setdefault("pylon.core", types.ModuleType("pylon.core"))
        sys.modules["pylon.core.tools"] = tools
    package = types.ModuleType(PACKAGE)
    package.__path__ = [str(UTILS_PATH)]
    sys.modules[PACKAGE] = package
    modules = {}
    for name in ("skill_files_backup", "project_backup", "chat_backup", "chat_restore", "project_restore"):
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
pb = MODULES["project_backup"]
pr = MODULES["project_restore"]


def sha(content):
    return hashlib.sha256(content).hexdigest()


class FakeStorage:
    """ One project's buckets; files maps (bucket, key) -> bytes """

    def __init__(self, files=None, fail=()):
        self.files = dict(files or {})
        self.buckets = {bucket for bucket, _ in self.files}
        self.fail = set(fail)
        self.removed = []

    def list_bucket(self):
        return sorted(self.buckets)

    def create_bucket(self, bucket, bucket_type=None, retention_days=None):
        self.buckets.add(bucket)

    def list_files(self, bucket):
        return [{"name": name, "size": len(data)} for (b, name), data in self.files.items() if b == bucket]

    def upload_file(self, bucket, content, name):
        if name in self.fail:
            raise RuntimeError("storage is down")
        self.files[(bucket, name)] = content

    def download_file(self, bucket, name, project_id=None):
        return self.files[(bucket, name)]

    def remove_file(self, bucket, name):
        self.removed.append((bucket, name))
        self.files.pop((bucket, name), None)


@pytest.fixture(scope="module")
def database():
    name = "elitea_test_7477_{}".format(uuid.uuid4().hex[:8])
    admin = psycopg2.connect(DSN)
    admin.autocommit = True
    with admin.cursor() as cursor:
        cursor.execute(psql.SQL("CREATE DATABASE {}").format(psql.Identifier(name)))
    dsn = psycopg2.extensions.parse_dsn(DSN)
    dsn["dbname"] = name
    yield dsn
    with admin.cursor() as cursor:
        cursor.execute(psql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(psql.Identifier(name)))
    admin.close()


@pytest.fixture()
def connection(database):
    connection = psycopg2.connect(**database)
    with connection.cursor() as cursor:
        for schema in (SOURCE, TARGET):
            cursor.execute("DROP SCHEMA IF EXISTS {} CASCADE".format(schema))
            cursor.execute("CREATE SCHEMA {}".format(schema))
            cursor.execute(DDL.format(s=schema))
        cursor.execute(
            "INSERT INTO {}.skills (name, description, owner_id, author_id, uuid)"
            " VALUES ('pdf', 'Reads PDFs', %s, 3, %s) RETURNING id".format(SOURCE),
            (SOURCE_ID, str(uuid.uuid4())),
        )
        skill_id = cursor.fetchone()[0]
        versions = []
        for name in ("base", "v2"):
            cursor.execute(
                "INSERT INTO {}.skill_versions (skill_id, name, instructions, author_id, uuid, status)"
                " VALUES (%s, %s, 'Use the guide', 3, %s, 'draft') RETURNING id".format(SOURCE),
                (skill_id, name, str(uuid.uuid4())),
            )
            versions.append(cursor.fetchone()[0])
        for version_id, path, content, is_text in (
                (versions[0], "references/guide.md", GUIDE, True),
                (versions[1], "references/guide.md", GUIDE, True),
                (versions[1], "assets/logo.bin", LOGO, False),
        ):
            cursor.execute(
                "INSERT INTO {}.skill_version_files (skill_version_id, path, size, sha256, content_type, is_text)"
                " VALUES (%s, %s, %s, %s, %s, %s)".format(SOURCE),
                (version_id, path, len(content), sha(content),
                 "text/markdown" if is_text else "application/octet-stream", is_text),
            )
    connection.commit()
    yield connection
    connection.close()


def _source_storage():
    return FakeStorage({(BUCKET, sha(GUIDE)): GUIDE, (BUCKET, sha(LOGO)): LOGO})


def _backup_zip(connection, storage):
    """ The backup archive as the endpoint streams it: one snapshot, hash list, members, SQL """
    sfb.begin_backup_snapshot(connection, SOURCE_ID)
    with connection.cursor() as cursor:
        skill_files = sfb.resolve_skill_files(cursor, SOURCE)
    sql_text = "".join(pb.iter_project_backup_sql(connection, SOURCE_ID, SOURCE, "Source"))
    connection.rollback()
    info = cb.make_info(SOURCE_ID, "Source", {}, cb.CHATS_NONE, {"chats_count": 0, "attachments": []}, skill_files)
    return b"".join(cb.iter_backup_zip(
        info, iter([sql_text.encode("utf-8")]), [], None, skill_files,
        lambda key: storage.download_file(BUCKET, key),
    ))


def _restore(connection, data, storage, dry_run=False, target=TARGET, target_id=TARGET_ID, truncate=False,
             handler=None):
    archive, _, _ = cr.open_backup_zip(io.BytesIO(data), 10 ** 9)
    text = b"".join(cr.iter_zip_sql(archive)()).decode("utf-8")
    handler = handler or sfb.SkillFileRestorer(lambda: storage, archive)
    return pr.restore_safe_backup(
        connection, open_chunks=lambda: iter([text]), schema=target, dry_run=dry_run, truncate=truncate,
        denied_tables=pr.SAFE_RESTORE_DENIED_TABLES, owner_user_id=RESTORER, owner_project_id=target_id,
        source_project_id=SOURCE_ID, skill_file_handler=handler, project_id=target_id,
    )


def _manifest(connection, schema):
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT v.name, f.path, f.sha256, f.size, f.is_text FROM {s}.skill_version_files f"
            " JOIN {s}.skill_versions v ON v.id = f.skill_version_id ORDER BY v.name, f.path".format(s=schema)
        )
        rows = cursor.fetchall()
    connection.rollback()
    return rows


def _add_file(connection, version_name, path, content):
    with connection.cursor() as cursor:
        cursor.execute(
            "INSERT INTO {s}.skill_version_files (skill_version_id, path, size, sha256, content_type, is_text)"
            " SELECT id, %s, %s, %s, 'text/markdown', true FROM {s}.skill_versions WHERE name = %s".format(s=SOURCE),
            (path, len(content), sha(content), version_name),
        )
    connection.commit()


def _deletes_held_off(database, project_id):
    """ Whether a core delete of the project's skill files would back off now """
    other = psycopg2.connect(**database)
    try:
        with other.cursor() as cursor:
            cursor.execute("SELECT pg_try_advisory_xact_lock({}, %s)".format(LOCK_KEY), (project_id,))
            return not cursor.fetchone()[0]
    finally:
        other.close()


def test_backup_sql_carries_the_manifest_rows(connection):
    text = "".join(pb.iter_project_backup_sql(connection, SOURCE_ID, SOURCE, "Source"))
    connection.rollback()
    assert 'COPY "skill_version_files" (' in text
    assert sha(LOGO) in text


def test_skill_file_paths_that_look_like_secrets_survive_backup_and_restore(connection):
    guidelines, template = b"# Tasks\n", b"# Risks\n"
    _add_file(connection, "v2", "references/task-management-guidelines.md", guidelines)
    _add_file(connection, "v2", "templates/risk-assessment-template.md", template)
    storage = _source_storage()
    storage.files.update({(BUCKET, sha(guidelines)): guidelines, (BUCKET, sha(template)): template})
    _restore(connection, _backup_zip(connection, storage), FakeStorage())
    paths = [row[1] for row in _manifest(connection, TARGET)]
    assert "references/task-management-guidelines.md" in paths
    assert "templates/risk-assessment-template.md" in paths
    assert _manifest(connection, TARGET) == _manifest(connection, SOURCE)


def test_the_hash_list_and_the_dumped_rows_come_from_one_snapshot(database, connection):
    sfb.begin_backup_snapshot(connection, SOURCE_ID)
    with connection.cursor() as cursor:
        hashes = {item["sha256"] for item in sfb.resolve_skill_files(cursor, SOURCE)}
    late = b"added while the backup ran"
    writer = psycopg2.connect(**database)
    _add_file(writer, "v2", "late.md", late)
    writer.close()
    text = "".join(pb.iter_project_backup_sql(connection, SOURCE_ID, SOURCE, "Source"))
    connection.rollback()
    assert sha(late) not in hashes
    assert sha(late) not in text


def test_the_backup_holds_core_skill_file_deletes_off_until_its_transaction_ends(database, connection):
    sfb.begin_backup_snapshot(connection, SOURCE_ID)
    assert _deletes_held_off(database, SOURCE_ID)
    assert not _deletes_held_off(database, TARGET_ID)
    connection.rollback()
    assert not _deletes_held_off(database, SOURCE_ID)


def test_restore_into_another_project_uploads_the_objects_and_keeps_the_manifest(connection):
    target_storage = FakeStorage()
    summary = _restore(connection, _backup_zip(connection, _source_storage()), target_storage)
    assert _manifest(connection, TARGET) == _manifest(connection, SOURCE)
    assert target_storage.files == {(BUCKET, sha(GUIDE)): GUIDE, (BUCKET, sha(LOGO)): LOGO}
    assert summary["skill_files"] == {
        "total": 2, "present": 0, "uploaded": 2, "missing": 0, "missing_paths": [], "unchecked": False,
    }
    assert summary["rows"]["skill_version_files"] == 3


def test_restore_into_the_source_project_reuses_its_objects(connection):
    storage = _source_storage()
    data = _backup_zip(connection, storage)
    with connection.cursor() as cursor:
        cursor.execute("TRUNCATE {}.skills RESTART IDENTITY CASCADE".format(SOURCE))
    connection.commit()
    before = dict(storage.files)
    summary = _restore(connection, data, storage, target=SOURCE, target_id=SOURCE_ID)
    assert (summary["skill_files"]["present"], summary["skill_files"]["uploaded"]) == (2, 0)
    assert storage.files == before
    assert len(_manifest(connection, SOURCE)) == 3


def test_dry_run_commits_no_rows_and_uploads_nothing(connection):
    target_storage = FakeStorage()
    summary = _restore(connection, _backup_zip(connection, _source_storage()), target_storage, dry_run=True)
    assert summary["skill_files"]["uploaded"] == 2
    assert target_storage.files == {} and target_storage.buckets == set()
    assert _manifest(connection, TARGET) == []


def test_upload_failure_rolls_back_the_rows_and_leaves_earlier_uploads_to_the_sweep(connection):
    first, second = sorted((sha(GUIDE), sha(LOGO)))
    target_storage = FakeStorage(fail={second})
    with pytest.raises(RuntimeError, match="storage is down"):
        _restore(connection, _backup_zip(connection, _source_storage()), target_storage)
    assert list(target_storage.files) == [(BUCKET, first)]
    assert target_storage.removed == []
    assert _manifest(connection, TARGET) == []


def test_a_failure_after_the_uploads_leaves_them_to_the_sweep(connection, monkeypatch):
    target_storage = FakeStorage()

    def explode(*args, **kwargs):
        raise RuntimeError("late failure")
    monkeypatch.setattr(pr, "_remap_project_reference_columns", explode)
    with pytest.raises(RuntimeError, match="late failure"):
        _restore(connection, _backup_zip(connection, _source_storage()), target_storage)
    assert set(target_storage.files) == {(BUCKET, sha(GUIDE)), (BUCKET, sha(LOGO))}
    assert target_storage.removed == []
    assert _manifest(connection, TARGET) == []


@pytest.mark.parametrize("target, target_id", [(TARGET, TARGET_ID), (SOURCE, SOURCE_ID)],
                         ids=["another project", "the source project"])
def test_the_restore_holds_core_skill_file_deletes_of_its_target_off(database, connection, target, target_id):
    data = _backup_zip(connection, _source_storage())
    seen = []
    restorer = sfb.SkillFileRestorer(lambda: FakeStorage(), cr.open_backup_zip(io.BytesIO(data), 10 ** 9)[0])

    def handler(cursor, dry_run):
        seen.append(_deletes_held_off(database, target_id))
        return restorer(cursor, dry_run)
    _restore(connection, data, None, target=target, target_id=target_id, handler=handler, dry_run=True)
    assert seen == [True]
    assert not _deletes_held_off(database, target_id)


def test_a_replace_restore_waits_for_a_core_delete_without_deadlocking(database, connection):
    data = _backup_zip(connection, _source_storage())
    deleter = psycopg2.connect(**database)
    with deleter.cursor() as cursor:
        cursor.execute("SELECT pg_advisory_xact_lock({}, %s)".format(LOCK_KEY), (TARGET_ID,))
    errors = []

    def restore():
        try:
            _restore(connection, data, FakeStorage(), truncate=True)
        except Exception as exc:  # pylint: disable=W0703
            errors.append(exc)
    thread = threading.Thread(target=restore)
    thread.start()
    time.sleep(0.5)
    try:
        with deleter.cursor() as cursor:
            cursor.execute("SELECT count(*) FROM {}.skill_version_files".format(TARGET))
        deleter.commit()
    except psycopg2.Error as exc:
        errors.append(exc)
    finally:
        deleter.close()
    thread.join(30)
    assert not thread.is_alive()
    assert errors == []
    assert len(_manifest(connection, TARGET)) == 3
