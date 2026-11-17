"""EL-7504: lifecycle audit storage in PostgreSQL (AC-10, AC-11, AC-12–AC-15, AC-17, AC-21, AC-22, AC-24).

A throwaway database is created next to the one in ELITEA_TEST_PG_DSN and dropped afterwards.

    ELITEA_TEST_PG_DSN="postgresql://centry:changeme@localhost:5432/db" \\
        python tests/run_tests.py integration/test_7504_lifecycle_audit_store.py

Skipped when the variable is not set.
"""
import csv
import datetime
import importlib
import io
import json
import os
import pathlib
import sys
import uuid

import pytest

psycopg2 = pytest.importorskip("psycopg2")
from psycopg2 import sql as psql  # noqa: E402  pylint: disable=C0413

DSN = os.environ.get("ELITEA_TEST_PG_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="ELITEA_TEST_PG_DSN is not set")

UTILS_PATH = pathlib.Path(__file__).resolve().parents[2] / "utils"
SCHEMA = "centry"
AUTH_SCHEMA = "public"
UTC = datetime.timezone.utc


def _load():
    sys.path.insert(0, str(UTILS_PATH))
    try:
        return importlib.import_module("lifecycle_audit")
    finally:
        sys.path.remove(str(UTILS_PATH))


la = _load()


@pytest.fixture(scope="module")
def database():
    name = "elitea_test_lifecycle_audit_{}".format(uuid.uuid4().hex[:8])
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
def conn(database):
    connection = psycopg2.connect(**database)
    with connection.cursor() as cursor:
        cursor.execute("DROP SCHEMA IF EXISTS centry CASCADE; CREATE SCHEMA centry")
        cursor.execute("DROP TABLE IF EXISTS public.auth_core__lifecycle_audit_inbox")
        cursor.execute(
            "CREATE TABLE public.auth_core__lifecycle_audit_inbox ("
            " id bigserial PRIMARY KEY, event_id varchar(36) NOT NULL UNIQUE,"
            " occurred_at timestamptz NOT NULL, event_type text NOT NULL, payload json NOT NULL)"
        )
    connection.commit()
    la.store.ensure_schema(connection, SCHEMA, today=datetime.date(2026, 11, 16), ahead_months=2)
    yield connection
    connection.close()


def event(event_type="project.member_added", when=None, **fields):
    payload = {
        "event_id": str(uuid.uuid4()),
        "occurred_at": (when or datetime.datetime(2026, 11, 16, 10, 0, tzinfo=UTC)).isoformat(),
        "event_type": event_type, "scope": "project", "source": "ui", "result": "success",
        "failure_reason": None, "imported": False,
        "actor_type": "user", "actor_id": 7, "actor_name": "Root Admin", "actor_email": "root@example.com",
        "request_id": "req-1",
        "project_id": 5, "project_name": "Alpha", "project_type": "team",
        "user_id": 11, "user_name": "Ann", "user_email": "ann@example.com",
        "roles_before": [], "roles_after": ["viewer"], "admin_access": None,
        "changes": {}, "details": {},
    }
    payload.update(fields)
    return payload


def auth_inbox(conn, payload):
    with conn.cursor() as cursor:
        cursor.execute(
            "INSERT INTO public.auth_core__lifecycle_audit_inbox (event_id, occurred_at, event_type, payload)"
            " VALUES (%s, %s, %s, %s)",
            (payload["event_id"], payload["occurred_at"], payload["event_type"], json.dumps(payload)),
        )
    conn.commit()


def drain(conn):
    return la.store.drain(conn, SCHEMA, AUTH_SCHEMA, batch_size=100)


def count(conn, table):
    with conn.cursor() as cursor:
        cursor.execute(f"SELECT count(*) FROM {table}")
        return cursor.fetchone()[0]


def query(conn, **params):
    params.setdefault("date_from", datetime.datetime(2026, 1, 1, tzinfo=UTC))
    params.setdefault("date_to", datetime.datetime(2027, 1, 1, tzinfo=UTC))
    return la.store.query(conn, SCHEMA, la.query.parse(params))


# --- partitions / provisioning (AC-22) -------------------------------------------

def test_partitions_cover_current_month_and_lookahead_without_default(conn):
    names = la.store.partition_names(conn, SCHEMA)
    assert names == ["admin_lifecycle_audit_event_202611", "admin_lifecycle_audit_event_202612",
                     "admin_lifecycle_audit_event_202701"]


def test_ensure_schema_is_idempotent_and_keeps_coverage_date(conn):
    first = la.store.coverage_since(conn, SCHEMA)
    la.store.ensure_schema(conn, SCHEMA, today=datetime.date(2026, 12, 1), ahead_months=2)
    assert la.store.coverage_since(conn, SCHEMA) == first
    assert "admin_lifecycle_audit_event_202702" in la.store.partition_names(conn, SCHEMA)


# --- append-only (AC-24) ----------------------------------------------------------

@pytest.mark.parametrize("statement", [
    "UPDATE centry.admin_lifecycle_audit_event SET user_name = 'x'",
    "DELETE FROM centry.admin_lifecycle_audit_event",
    "TRUNCATE centry.admin_lifecycle_audit_event",
    "UPDATE centry.admin_lifecycle_audit_event_202611 SET user_name = 'x'",
    "DELETE FROM centry.admin_lifecycle_audit_event_202611",
])
def test_rows_cannot_be_changed(conn, statement):
    la.store.record(conn, SCHEMA, [event()])
    conn.commit()
    drain(conn)
    with pytest.raises(psycopg2.Error):
        with conn.cursor() as cursor:
            cursor.execute(statement)
    conn.rollback()
    assert count(conn, "centry.admin_lifecycle_audit_event") == 1


# --- write path / drainer (AC-10) ---------------------------------------------------

def test_admin_and_auth_inboxes_drain_into_partitioned_table(conn):
    la.store.record(conn, SCHEMA, [event(user_id=1)])
    conn.commit()
    auth_inbox(conn, event(user_id=2))

    assert drain(conn) == 2

    assert count(conn, "centry.admin_lifecycle_audit_event_202611") == 2
    assert count(conn, "centry.admin_lifecycle_audit_inbox") == 0
    assert count(conn, "public.auth_core__lifecycle_audit_inbox") == 0


def test_record_is_part_of_the_callers_transaction(conn):
    la.store.record(conn, SCHEMA, [event()])
    conn.rollback()
    assert drain(conn) == 0
    assert count(conn, "centry.admin_lifecycle_audit_event") == 0


def test_redrain_of_same_event_is_idempotent(conn):
    payload = event()
    auth_inbox(conn, payload)
    drain(conn)
    auth_inbox(conn, payload)

    drain(conn)

    assert count(conn, "centry.admin_lifecycle_audit_event") == 1


def test_missing_partition_keeps_event_in_inbox(conn):
    far = event(when=datetime.datetime(2031, 5, 1, tzinfo=UTC))
    auth_inbox(conn, far)
    auth_inbox(conn, event())

    drained = drain(conn)

    assert drained == 1
    assert count(conn, "public.auth_core__lifecycle_audit_inbox") == 1
    la.store.ensure_partitions(conn, SCHEMA, (2031, 5), (2031, 5))
    assert drain(conn) == 1
    assert count(conn, "public.auth_core__lifecycle_audit_inbox") == 0


def test_drain_without_auth_inbox_still_drains_admin_inbox(conn):
    with conn.cursor() as cursor:
        cursor.execute("DROP TABLE public.auth_core__lifecycle_audit_inbox")
    conn.commit()
    la.store.record(conn, SCHEMA, [event()])
    conn.commit()

    assert drain(conn) == 1


# --- retention (AC-22) --------------------------------------------------------------

def test_retention_none_keeps_everything(conn):
    la.store.ensure_partitions(conn, SCHEMA, (2024, 1), (2024, 2))
    assert la.store.apply_retention(conn, SCHEMA, None, today=datetime.date(2026, 11, 16)) == []
    assert "admin_lifecycle_audit_event_202401" in la.store.partition_names(conn, SCHEMA)


def test_retention_drops_only_whole_expired_months(conn):
    la.store.ensure_partitions(conn, SCHEMA, (2025, 9), (2025, 11))
    auth_inbox(conn, event(when=datetime.datetime(2025, 10, 31, 23, 59, tzinfo=UTC)))
    auth_inbox(conn, event(when=datetime.datetime(2025, 11, 1, 0, 0, tzinfo=UTC)))
    drain(conn)

    dropped = la.store.apply_retention(conn, SCHEMA, 12, today=datetime.date(2026, 11, 16))

    assert dropped == ["admin_lifecycle_audit_event_202509", "admin_lifecycle_audit_event_202510"]
    names = la.store.partition_names(conn, SCHEMA)
    assert "admin_lifecycle_audit_event_202511" in names
    assert count(conn, "centry.admin_lifecycle_audit_event") == 1


# --- read API (AC-3, AC-11–AC-15, AC-21) ---------------------------------------------

@pytest.fixture()
def seeded(conn):
    rows = [
        event("project.created", user_id=None, user_name=None, user_email=None,
              when=datetime.datetime(2026, 11, 1, 9, tzinfo=UTC), roles_after=None,
              details={"owner": {"id": 11}, "creator": {"id": 7}}),
        event("project.member_added", when=datetime.datetime(2026, 11, 2, 9, tzinfo=UTC)),
        event("project.member_role_changed", when=datetime.datetime(2026, 11, 3, 9, tzinfo=UTC),
              roles_before=["viewer"], roles_after=["admin"], admin_access="granted"),
        event("user.email_changed", project_id=None, project_name=None, project_type=None,
              scope="platform", when=datetime.datetime(2026, 11, 4, 9, tzinfo=UTC),
              user_email="ann.b@example.com",
              changes={"email": {"before": "ann@example.com", "after": "ann.b@example.com"}}),
        event("project.renamed", user_id=None, user_name=None, user_email=None, project_name="Beta",
              when=datetime.datetime(2026, 11, 5, 9, tzinfo=UTC),
              changes={"name": {"before": "Alpha", "after": "Beta"}}),
        event("user.platform_role_changed", project_id=None, project_name=None, project_type=None,
              scope="platform", source="provisioning", actor_type="service", actor_id=None,
              actor_name="SCIM", when=datetime.datetime(2026, 11, 6, 9, tzinfo=UTC),
              user_id=12, user_name="Bob", user_email="bob@example.com",
              roles_before=["super_admin"], roles_after=[], admin_access="revoked"),
    ]
    la.store.record(conn, SCHEMA, rows)
    conn.commit()
    drain(conn)
    return rows


def types_of(result):
    return [row["event_type"] for row in result["rows"]]


def test_tabs_share_membership_rows_newest_first(conn, seeded):
    projects = query(conn, tab="projects")
    users = query(conn, tab="users")

    assert types_of(projects) == ["project.renamed", "project.member_role_changed",
                                  "project.member_added", "project.created"]
    assert types_of(users) == ["user.platform_role_changed", "user.email_changed",
                               "project.member_role_changed", "project.member_added"]
    shared = {r["event_id"] for r in projects["rows"]} & {r["event_id"] for r in users["rows"]}
    assert len(shared) == 2


def test_admin_access_filter_spans_project_and_platform(conn, seeded):
    result = query(conn, tab="users", admin_access="any")
    assert types_of(result) == ["user.platform_role_changed", "project.member_role_changed"]


@pytest.mark.parametrize("q, expected", [
    ("ann@example.com", {"user.email_changed", "project.member_added", "project.member_role_changed"}),
    ("alpha", {"project.created", "project.member_added", "project.member_role_changed", "project.renamed"}),
    ("SCIM", {"user.platform_role_changed"}),
])
def test_free_text_matches_previous_values(conn, seeded, q, expected):
    assert set(types_of(query(conn, q=q))) == expected


def test_combined_filters(conn, seeded):
    result = query(conn, tab="users", source="provisioning", event_type=["user.platform_role_changed"],
                   actor="scim", user_email="bob@")
    assert result["total"] == 1


def test_sort_and_pagination(conn, seeded):
    result = query(conn, tab="projects", sort_by="event_type", sort_order="asc", limit=2, offset=1)
    assert result["total"] == 4
    assert types_of(result) == ["project.member_added", "project.member_role_changed"]


def test_unknown_sort_column_falls_back_to_time(conn, seeded):
    result = query(conn, tab="projects", sort_by="payload; DROP TABLE x", sort_order="asc")
    assert types_of(result)[0] == "project.created"


def test_date_range_is_required_unless_all_time(conn, seeded):
    with pytest.raises(ValueError):
        la.query.parse({"tab": "projects"})
    assert la.store.query(conn, SCHEMA, la.query.parse({"tab": "projects", "all_time": "true"}))["total"] == 4


def test_coverage_date_returned_and_live_rows_not_imported(conn, seeded):
    result = query(conn, tab="users")
    assert result["live_coverage_since"] is not None
    assert all(row["imported"] is False for row in result["rows"])


# --- export (AC-17) -------------------------------------------------------------------

def test_csv_export_respects_filters_sort_and_utc(conn, seeded):
    lines = "".join(la.store.export_csv(conn, SCHEMA, la.query.parse({
        "tab": "projects", "sort_by": "time", "sort_order": "asc",
        "date_from": "2026-01-01T00:00:00Z", "date_to": "2027-01-01T00:00:00Z",
    })))
    rows = list(csv.DictReader(io.StringIO(lines)))
    assert [r["event_type"] for r in rows][0] == "project.created"
    assert len(rows) == 4
    assert rows[0]["occurred_at"].endswith("+00:00")


def test_csv_export_neutralises_formulas(conn):
    la.store.record(conn, SCHEMA, [event(user_name="=HYPERLINK(\"x\")")])
    conn.commit()
    drain(conn)
    lines = "".join(la.store.export_csv(conn, SCHEMA, la.query.parse({"tab": "users", "all_time": "1"})))
    assert "'=HYPERLINK" in lines
