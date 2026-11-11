"""Integration tests for EL-TBD - restore job state in PostgreSQL (AC-3, AC-4, AC-7, Q2).

A throwaway database is created next to the one in ELITEA_TEST_PG_DSN and
dropped afterwards; utils/restore_jobs.py creates its table there.

    ELITEA_TEST_PG_DSN="postgresql://centry:changeme@localhost:5432/db" \\
        python tests/run_tests.py integration/test_restore_jobs_db.py

Skipped when the variable is not set.
"""
import importlib.util
import os
import pathlib
import sys
import types
import uuid

import pytest

psycopg2 = pytest.importorskip("psycopg2")
from psycopg2 import sql as psql  # noqa: E402  pylint: disable=C0413


DSN = os.environ.get("ELITEA_TEST_PG_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="ELITEA_TEST_PG_DSN is not set")

UTILS_PATH = pathlib.Path(__file__).resolve().parents[2] / "utils"
SCHEMA = "centry"


def _load():
    if "pylon.core.tools" not in sys.modules:
        tools = types.ModuleType("pylon.core.tools")
        tools.log = types.SimpleNamespace(
            info=lambda *a, **k: None, warning=lambda *a, **k: None,
            error=lambda *a, **k: None, exception=lambda *a, **k: None,
        )
        sys.modules.setdefault("pylon", types.ModuleType("pylon"))
        sys.modules.setdefault("pylon.core", types.ModuleType("pylon.core"))
        sys.modules["pylon.core.tools"] = tools
    spec = importlib.util.spec_from_file_location("_admin_restore_jobs_it", UTILS_PATH / "restore_jobs.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


rj = _load()


@pytest.fixture(scope="module")
def database():
    name = "elitea_test_restore_jobs_{}".format(uuid.uuid4().hex[:8])
    admin = psycopg2.connect(DSN)
    admin.autocommit = True
    with admin.cursor() as cursor:
        cursor.execute(psql.SQL("CREATE DATABASE {}").format(psql.Identifier(name)))
    dsn = psycopg2.extensions.parse_dsn(DSN)
    dsn["dbname"] = name
    connection = psycopg2.connect(**dsn)
    with connection.cursor() as cursor:
        cursor.execute("CREATE SCHEMA {}".format(SCHEMA))
    connection.commit()
    rj.ensure_table(connection, SCHEMA)
    rj.ensure_table(connection, SCHEMA)  # idempotent
    connection.close()
    yield dsn
    with admin.cursor() as cursor:
        cursor.execute(psql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(psql.Identifier(name)))
    admin.close()


@pytest.fixture()
def jobs(database):
    connection = psycopg2.connect(**database)
    store = rj.JobStore(lambda: connection, SCHEMA)
    with connection.cursor() as cursor:
        cursor.execute("DELETE FROM {}.{}".format(SCHEMA, rj.TABLE))
    connection.commit()
    yield store, connection
    connection.close()


def _create(store, project_id=12, **kwargs):
    defaults = {"user_id": 3, "mode": "safe", "options": {"truncate": True}, "artifact": {"kind": "safe"}}
    defaults.update(kwargs)
    return store.create(project_id=project_id, **defaults)


def _set(connection, job_id, **columns):
    assignments = ", ".join("{} = {}".format(name, value) for name, value in columns.items())
    with connection.cursor() as cursor:
        cursor.execute("UPDATE {}.{} SET {} WHERE id = %s".format(SCHEMA, rj.TABLE, assignments), (job_id,))
    connection.commit()


def test_create_returns_a_queued_job(jobs):
    store, _ = jobs
    job = _create(store)
    assert job["status"] == rj.STATUS_QUEUED
    assert job["project_id"] == 12
    assert job["artifact"] == {"kind": "safe"}
    assert job["options"] == {"truncate": True}
    assert store.get(job["id"])["status"] == rj.STATUS_QUEUED


def test_second_active_job_for_the_same_project_is_refused(jobs):
    store, _ = jobs
    first = _create(store)
    with pytest.raises(rj.RestoreInProgress) as error:
        _create(store)
    assert error.value.job_id == first["id"]


def test_other_projects_are_not_blocked(jobs):
    store, _ = jobs
    _create(store, project_id=12)
    assert _create(store, project_id=13)["status"] == rj.STATUS_QUEUED


def test_a_finished_job_frees_the_project(jobs):
    store, _ = jobs
    first = _create(store)
    store.start(first["id"])
    store.finish(first["id"], result={"total_rows": 5}, status_code=200)
    second = _create(store)
    assert second["id"] != first["id"]


def test_lifecycle_done(jobs):
    store, _ = jobs
    job = _create(store)
    store.start(job["id"])
    running = store.get(job["id"])
    assert running["status"] == rj.STATUS_RUNNING
    assert running["started_at"] is not None
    store.heartbeat(job["id"])
    store.finish(job["id"], result={"total_rows": 5, "dry_run": False}, status_code=200)
    done = store.get(job["id"])
    assert done["status"] == rj.STATUS_DONE
    assert done["result"] == {"total_rows": 5, "dry_run": False}
    assert done["status_code"] == 200
    assert done["finished_at"] is not None


def test_lifecycle_failed_keeps_the_response_body(jobs):
    store, _ = jobs
    job = _create(store)
    store.start(job["id"])
    store.fail(job["id"], error="insert failed on tags", status_code=400, body={"ok": False, "error": "x"})
    failed = store.get(job["id"])
    assert failed["status"] == rj.STATUS_FAILED
    assert failed["error"] == "insert failed on tags"
    assert failed["status_code"] == 400
    assert failed["result"] == {"ok": False, "error": "x"}


def test_finish_does_not_resurrect_a_reaped_job(jobs):
    store, connection = jobs
    job = _create(store)
    store.start(job["id"])
    _set(connection, job["id"], heartbeat_at="now() - interval '1 hour'")
    store.reap(stale_after_seconds=600, retention_days=7)
    store.finish(job["id"], result={}, status_code=200)
    assert store.get(job["id"])["status"] == rj.STATUS_FAILED


def test_reap_fails_stale_running_and_queued_jobs(jobs):
    store, connection = jobs
    running = _create(store, project_id=1)
    store.start(running["id"])
    _set(connection, running["id"], heartbeat_at="now() - interval '11 minutes'")
    queued = _create(store, project_id=2)
    _set(connection, queued["id"], created_at="now() - interval '11 minutes'")
    fresh = _create(store, project_id=3)
    store.start(fresh["id"])
    #
    summary = store.reap(stale_after_seconds=600, retention_days=7)
    assert summary["failed"] == 2
    assert store.get(running["id"])["status"] == rj.STATUS_FAILED
    assert store.get(queued["id"])["status"] == rj.STATUS_FAILED
    assert store.get(running["id"])["error"] == rj.STALE_ERROR
    assert store.get(fresh["id"])["status"] == rj.STATUS_RUNNING
    # the project of a reaped job can be restored again
    assert _create(store, project_id=1)["status"] == rj.STATUS_QUEUED


def test_reap_deletes_finished_jobs_past_retention(jobs):
    store, connection = jobs
    old = _create(store, project_id=1)
    store.finish(old["id"], result={}, status_code=200)
    _set(connection, old["id"], finished_at="now() - interval '8 days'")
    recent = _create(store, project_id=2)
    store.finish(recent["id"], result={}, status_code=200)
    #
    summary = store.reap(stale_after_seconds=600, retention_days=7)
    assert summary["deleted"] == 1
    assert store.get(old["id"]) is None
    assert store.get(recent["id"]) is not None


def test_job_is_scoped_to_its_project(jobs):
    store, _ = jobs
    job = _create(store, project_id=12)
    assert store.get(job["id"], project_id=12) is not None
    assert store.get(job["id"], project_id=13) is None
