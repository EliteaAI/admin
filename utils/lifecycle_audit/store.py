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

""" Lifecycle audit storage

Writers put events into an inbox in the transaction of the change: ``admin_lifecycle_audit_inbox``
here, ``auth_core__lifecycle_audit_inbox`` in pylon_auth. drain() moves them into the monthly
range-partitioned ``admin_lifecycle_audit_event``, idempotently on event_id. An event whose month has
no partition yet stays in its inbox (no DEFAULT partition) until ensure_partitions() creates it.

The event table is append-only: triggers reject UPDATE / DELETE / TRUNCATE. Retention detaches and
drops whole months. Tables, indexes and triggers are created by ensure_schema() from the
``lifecycle_audit_provision`` admin task, never at plugin start; the daily cron only adds partitions.
Everything takes a psycopg2 connection; only ensure_* / drain / apply_retention commit, record()
leaves the commit to its caller.
"""

import csv
import datetime
import io
import json

from psycopg2 import extras, sql  # pylint: disable=E0401

from . import events as audit_events

EVENT_TABLE = "admin_lifecycle_audit_event"
INBOX_TABLE = "admin_lifecycle_audit_inbox"
META_TABLE = "admin_lifecycle_audit_meta"
AUTH_INBOX_TABLE = "auth_core__lifecycle_audit_inbox"
PROJECT_TABLE = "project"
GUARD_FUNCTION = "admin_lifecycle_audit_append_only"

UTC = datetime.timezone.utc

COLUMNS = (
    "event_id", "occurred_at", "event_type", "scope", "source", "result", "failure_reason",
    "actor_type", "actor_id", "actor_name", "actor_email",
    "project_id", "project_name", "project_type", "user_id", "user_name", "user_email",
    "admin_access", "roles_before", "roles_after", "changes", "details", "request_id", "imported",
)

DDL = """
CREATE TABLE IF NOT EXISTS {event} (
    event_id uuid NOT NULL,
    occurred_at timestamptz NOT NULL,
    event_type text NOT NULL,
    scope text NOT NULL,
    source text,
    result text NOT NULL DEFAULT 'success',
    failure_reason text,
    actor_type text NOT NULL,
    actor_id integer,
    actor_name text,
    actor_email text,
    project_id integer,
    project_name text,
    project_type text,
    user_id integer,
    user_name text,
    user_email text,
    admin_access text,
    roles_before text[],
    roles_after text[],
    changes jsonb NOT NULL DEFAULT '{{}}',
    details jsonb NOT NULL DEFAULT '{{}}',
    request_id text,
    imported boolean NOT NULL DEFAULT false,
    search_text text NOT NULL DEFAULT '',
    PRIMARY KEY (event_id, occurred_at)
) PARTITION BY RANGE (occurred_at);
CREATE INDEX IF NOT EXISTS admin_lifecycle_audit_event_time ON {event} (occurred_at DESC);
CREATE INDEX IF NOT EXISTS admin_lifecycle_audit_event_type ON {event} (event_type, occurred_at);
CREATE INDEX IF NOT EXISTS admin_lifecycle_audit_event_project ON {event} (project_id, occurred_at);
CREATE INDEX IF NOT EXISTS admin_lifecycle_audit_event_user ON {event} (user_id, occurred_at);
CREATE INDEX IF NOT EXISTS admin_lifecycle_audit_event_actor ON {event} (actor_id, occurred_at);
CREATE INDEX IF NOT EXISTS admin_lifecycle_audit_event_admin
    ON {event} (admin_access, occurred_at) WHERE admin_access IS NOT NULL;

CREATE TABLE IF NOT EXISTS {inbox} (
    id bigserial PRIMARY KEY,
    event_id varchar(36) NOT NULL UNIQUE,
    occurred_at timestamptz NOT NULL,
    event_type text NOT NULL,
    payload jsonb NOT NULL
);

CREATE TABLE IF NOT EXISTS {meta} (
    id integer PRIMARY KEY CHECK (id = 1),
    live_coverage_since timestamptz NOT NULL
);
INSERT INTO {meta} (id, live_coverage_since) VALUES (1, now()) ON CONFLICT (id) DO NOTHING;

CREATE OR REPLACE FUNCTION {guard}() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'lifecycle audit records are append-only (% on %)', TG_OP, TG_TABLE_NAME;
END
$$;
CREATE OR REPLACE TRIGGER admin_lifecycle_audit_no_change
    BEFORE UPDATE OR DELETE ON {event} FOR EACH ROW EXECUTE FUNCTION {guard}();
CREATE OR REPLACE TRIGGER admin_lifecycle_audit_no_truncate
    BEFORE TRUNCATE ON {event} FOR EACH STATEMENT EXECUTE FUNCTION {guard}();
"""

# Free-text search (q); skipped with a warning where the extension can not be created
TRGM_DDL = """
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX IF NOT EXISTS admin_lifecycle_audit_event_search
    ON {event} USING gin (search_text gin_trgm_ops);
"""

CSV_COLUMNS = COLUMNS
CSV_UNSAFE_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _ident(schema, name):
    return sql.Identifier(schema, name)


#
# Partitions
#

def next_month(year, month):
    """ The month after (year, month) """
    return (year + 1, 1) if month == 12 else (year, month + 1)


def add_months(year, month, count):
    """ (year, month) moved by count months, either direction """
    index = year * 12 + (month - 1) + count
    return index // 12, index % 12 + 1


def partition_name(year, month):
    """ Child table of one month """
    return f"{EVENT_TABLE}_{year:04d}{month:02d}"


def _month_of(name):
    suffix = name[len(EVENT_TABLE) + 1:]
    return int(suffix[:4]), int(suffix[4:6])


def partition_names(connection, schema):
    """ Attached partitions of the event table, oldest first """
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT c.relname FROM pg_inherits i"
            " JOIN pg_class c ON c.oid = i.inhrelid"
            " JOIN pg_class p ON p.oid = i.inhparent"
            " JOIN pg_namespace n ON n.oid = p.relnamespace"
            " WHERE n.nspname = %s AND p.relname = %s",
            (schema, EVENT_TABLE),
        )
        return sorted(row[0] for row in cursor.fetchall())


def ensure_partitions(connection, schema, from_month, to_month):
    """ Create the missing monthly partitions in [from_month, to_month]; bounds are UTC; commits

    Existing partitions are left alone, so the daily run takes no lock on live tables.
    """
    created = []
    current = tuple(from_month)
    existing = set(partition_names(connection, schema))
    with connection.cursor() as cursor:
        while current <= tuple(to_month):
            start = datetime.datetime(current[0], current[1], 1, tzinfo=UTC)
            end = datetime.datetime(*next_month(*current), 1, tzinfo=UTC)
            name = partition_name(*current)
            if name in existing:
                current = next_month(*current)
                continue
            cursor.execute(sql.SQL(
                "CREATE TABLE IF NOT EXISTS {child} PARTITION OF {parent} FOR VALUES FROM (%s) TO (%s)"
            ).format(child=_ident(schema, name), parent=_ident(schema, EVENT_TABLE)), (start, end))
            # A statement trigger on the parent does not fire for TRUNCATE of a partition
            cursor.execute(sql.SQL(
                "CREATE OR REPLACE TRIGGER admin_lifecycle_audit_no_truncate"
                " BEFORE TRUNCATE ON {child} FOR EACH STATEMENT EXECUTE FUNCTION {guard}()"
            ).format(child=_ident(schema, name), guard=_ident(schema, GUARD_FUNCTION)))
            created.append(name)
            current = next_month(*current)
    connection.commit()
    return created


def schema_ready(connection, schema):
    """ Whether ensure_schema() has run: a catalog read, no lock """
    with connection.cursor() as cursor:
        cursor.execute("SELECT to_regclass(%s), to_regclass(%s)", (
            f'"{schema}"."{EVENT_TABLE}"', f'"{schema}"."{INBOX_TABLE}"',
        ))
        ready = all(value is not None for value in cursor.fetchone())
    connection.commit()
    return ready


def ensure_lookahead(connection, schema, today=None, ahead_months=2):
    """ Current and next ahead_months partitions (daily cron) """
    today = today or datetime.datetime.now(UTC).date()
    current = (today.year, today.month)
    return ensure_partitions(connection, schema, current, add_months(*current, max(int(ahead_months), 0)))


def ensure_schema(connection, schema, today=None, ahead_months=2, log=None):
    """ Tables, indexes, append-only triggers, coverage date and partitions; idempotent; commits

    Admin task only: it replaces triggers, which locks the event table.
    """
    with connection.cursor() as cursor:
        cursor.execute(sql.SQL(DDL).format(
            event=_ident(schema, EVENT_TABLE),
            inbox=_ident(schema, INBOX_TABLE),
            meta=_ident(schema, META_TABLE),
            guard=_ident(schema, GUARD_FUNCTION),
        ))
    connection.commit()
    try:
        with connection.cursor() as cursor:
            cursor.execute(sql.SQL(TRGM_DDL).format(event=_ident(schema, EVENT_TABLE)))
        connection.commit()
    except Exception:  # pylint: disable=W0703
        connection.rollback()
        if log is not None:
            log.warning("pg_trgm is not available: free-text search runs without an index")
    return ensure_lookahead(connection, schema, today=today, ahead_months=ahead_months)


def coverage_since(connection, schema):
    """ When live capture started """
    with connection.cursor() as cursor:
        cursor.execute(sql.SQL("SELECT live_coverage_since FROM {} WHERE id = 1").format(
            _ident(schema, META_TABLE)))
        row = cursor.fetchone()
    return None if row is None else row[0]


def apply_retention(connection, schema, retention_months, today=None, keep_detached=False):
    """ Detach (and drop) months that end before today - retention_months; never deletes rows

    retention_months None keeps everything. Commits. Returns the affected partition names.
    """
    if retention_months is None:
        return []
    retention_months = int(retention_months)
    if retention_months < 1:
        raise ValueError("retention_months must be at least 1")
    today = today or datetime.datetime.now(UTC).date()
    year, month = add_months(today.year, today.month, -retention_months)
    cutoff = datetime.date(year, month, min(today.day, 28))
    #
    expired = []
    for name in partition_names(connection, schema):
        end = datetime.date(*next_month(*_month_of(name)), 1)
        if end <= cutoff:
            expired.append(name)
    #
    with connection.cursor() as cursor:
        for name in expired:
            cursor.execute(sql.SQL("ALTER TABLE {} DETACH PARTITION {}").format(
                _ident(schema, EVENT_TABLE), _ident(schema, name)))
            if not keep_detached:
                cursor.execute(sql.SQL("DROP TABLE {}").format(_ident(schema, name)))
    connection.commit()
    return expired


#
# Write path
#

def record(connection, schema, events):
    """ Add events to the admin inbox on the caller's transaction (no commit); returns success

    Runs in a savepoint: a failed insert is rolled back alone, so an audit outage never
    aborts the caller's change (AC-23).
    """
    events = [event for event in events if event]
    if not events:
        return True
    with connection.cursor() as cursor:
        cursor.execute("SAVEPOINT lifecycle_audit_record")
        try:
            extras.execute_batch(cursor, sql.SQL(
                "INSERT INTO {} (event_id, occurred_at, event_type, payload) VALUES (%s, %s, %s, %s)"
            ).format(_ident(schema, INBOX_TABLE)).as_string(cursor), [
                (event["event_id"], event["occurred_at"], event["event_type"], extras.Json(event))
                for event in events
            ])
        except Exception:  # pylint: disable=W0703
            cursor.execute("ROLLBACK TO SAVEPOINT lifecycle_audit_record")
            return False
        cursor.execute("RELEASE SAVEPOINT lifecycle_audit_record")
    return True


def search_text(event):
    """ Lower-cased names, ids, emails, roles and every before / after value """
    parts = [event.get(key) for key in (
        "event_type", "project_id", "project_name", "user_id", "user_name", "user_email",
        "actor_id", "actor_name", "actor_email", "request_id",
    )]
    parts += list(event.get("roles_before") or []) + list(event.get("roles_after") or [])
    for change in (event.get("changes") or {}).values():
        if isinstance(change, dict):
            parts += [change.get("before"), change.get("after")]
    return " ".join(str(part) for part in parts if part not in (None, "")).lower()


def _row_values(event):
    values = [event.get(column) for column in COLUMNS]
    index = {column: position for position, column in enumerate(COLUMNS)}
    values[index["changes"]] = extras.Json(event.get("changes") or {})
    values[index["details"]] = extras.Json(event.get("details") or {})
    values[index["imported"]] = bool(event.get("imported"))
    values[index["result"]] = event.get("result") or "success"
    values[index["actor_type"]] = event.get("actor_type") or "unknown"
    return values + [search_text(event)]


def _inboxes(connection, schema, auth_schema):
    """ Own inbox plus auth_core's in the configured auth_schema, when it exists """
    tables = [_ident(schema, INBOX_TABLE)]
    with connection.cursor() as cursor:
        cursor.execute("SELECT to_regclass(%s)", (f'"{auth_schema}"."{AUTH_INBOX_TABLE}"',))
        if cursor.fetchone()[0] is not None:
            tables.append(_ident(auth_schema, AUTH_INBOX_TABLE))
    connection.commit()
    return tables


def _project_names(cursor, schema, payloads):
    """ {project_id: name} for payloads that carry a project id but no name (auth_core writers) """
    ids = sorted({
        payload["project_id"] for payload in payloads
        if payload.get("project_id") is not None and not payload.get("project_name")
    })
    if not ids:
        return {}
    names = {}
    cursor.execute("SELECT to_regclass(%s)", (f'"{schema}"."{PROJECT_TABLE}"',))
    if cursor.fetchone()[0] is not None:
        cursor.execute(sql.SQL("SELECT id, name FROM {} WHERE id = ANY(%s)").format(
            _ident(schema, PROJECT_TABLE),
        ), (ids,))
        names.update(cursor.fetchall())
    # A deleted project keeps the last name its own audit history recorded
    gone = [project_id for project_id in ids if project_id not in names]
    if gone:
        cursor.execute(sql.SQL(
            "SELECT DISTINCT ON (project_id) project_id, project_name FROM {}"
            " WHERE project_id = ANY(%s) AND project_name IS NOT NULL"
            " ORDER BY project_id, occurred_at DESC"
        ).format(_ident(schema, EVENT_TABLE)), (gone,))
        names.update(cursor.fetchall())
    return names


def _with_project(payload, names):
    name = names.get(payload.get("project_id"))
    if payload.get("project_name") or name is None:
        return payload
    return dict(payload, project_name=name)


def drain(connection, schema, auth_schema, batch_size=500, missing=None):
    """ Move inbox rows into the event table; returns how many inbox rows were moved

    Safe on several replicas (SKIP LOCKED). Rows of a month without a partition are left in place and
    their (year, month) is added to ``missing`` when a set is given.
    """
    months = {_month_of(name) for name in partition_names(connection, schema)}
    connection.commit()
    insert = sql.SQL("INSERT INTO {} ({}) VALUES ({}) ON CONFLICT DO NOTHING").format(
        _ident(schema, EVENT_TABLE),
        sql.SQL(", ").join(sql.Identifier(column) for column in COLUMNS + ("search_text",)),
        sql.SQL(", ").join(sql.Placeholder() for _ in range(len(COLUMNS) + 1)),
    )
    moved = 0
    for inbox in _inboxes(connection, schema, auth_schema):
        last_id = 0
        while True:
            with connection.cursor() as cursor:
                cursor.execute(sql.SQL(
                    "SELECT id, occurred_at, payload FROM {} WHERE id > %s ORDER BY id LIMIT %s"
                    " FOR UPDATE SKIP LOCKED"
                ).format(inbox), (last_id, batch_size))
                rows = cursor.fetchall()
                if not rows:
                    connection.commit()
                    break
                last_id = rows[-1][0]
                rows = [
                    (row_id, occurred_at, json.loads(payload) if isinstance(payload, str) else payload)
                    for row_id, occurred_at, payload in rows
                ]
                names = _project_names(cursor, schema, [payload for _, _, payload in rows])
                ready, values = [], []
                for row_id, occurred_at, payload in rows:
                    payload = audit_events.normalize(_with_project(payload, names))
                    when = occurred_at.astimezone(UTC)
                    if (when.year, when.month) not in months:
                        if missing is not None:
                            missing.add((when.year, when.month))
                        continue
                    ready.append(row_id)
                    values.append(_row_values(dict(payload, occurred_at=when)))
                if values:
                    extras.execute_batch(cursor, insert.as_string(cursor), values)
                    cursor.execute(sql.SQL("DELETE FROM {} WHERE id = ANY(%s)").format(inbox), (ready,))
            connection.commit()
            moved += len(ready)
    return moved


#
# Reads
#

def _like(value):
    return "%" + value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _where(params):  # pylint: disable=R0912
    clauses, args = [], []
    if params.get("tab") == "projects":
        clauses.append("project_id IS NOT NULL")
    elif params.get("tab") == "users":
        clauses.append("user_id IS NOT NULL")
    if params.get("date_from") is not None:
        clauses.append("occurred_at >= %s")
        args.append(params["date_from"])
    if params.get("date_to") is not None:
        clauses.append("occurred_at < %s")
        args.append(params["date_to"])
    if params.get("event_type"):
        clauses.append("event_type = ANY(%s)")
        args.append(list(params["event_type"]))
    for name in ("project_id", "user_id"):
        if params.get(name) is not None:
            clauses.append(f"{name} = %s")
            args.append(params[name])
    for name in ("project_name", "user_name", "user_email"):
        if params.get(name):
            clauses.append(f"{name} ILIKE %s")
            args.append(_like(params[name]))
    for name in ("project_type", "result", "source"):
        if params.get(name):
            clauses.append(f"{name} = %s")
            args.append(params[name])
    if params.get("actor"):
        clauses.append("(actor_name ILIKE %s OR actor_email ILIKE %s OR actor_id::text = %s)")
        args += [_like(params["actor"]), _like(params["actor"]), params["actor"]]
    if params.get("role"):
        clauses.append("(%s = ANY(roles_before) OR %s = ANY(roles_after))")
        args += [params["role"], params["role"]]
    if params.get("admin_access") == "any":
        clauses.append("admin_access IS NOT NULL")
    elif params.get("admin_access"):
        clauses.append("admin_access = %s")
        args.append(params["admin_access"])
    if params.get("imported") is not None:
        clauses.append("imported = %s")
        args.append(params["imported"])
    if params.get("q"):
        clauses.append("search_text LIKE %s")
        args.append(_like(params["q"]))
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", args


def _order(params):
    column = params.get("sort_by") or "occurred_at"
    direction = "ASC" if params.get("sort_order") == "asc" else "DESC"
    # column comes from query.SORT_COLUMNS only
    return sql.SQL(" ORDER BY {} {} NULLS LAST, occurred_at DESC, event_id").format(
        sql.Identifier(column), sql.SQL(direction))


def _serialize(row):
    result = dict(row)
    result["event_id"] = str(result["event_id"])
    result["occurred_at"] = result["occurred_at"].astimezone(UTC).isoformat()
    return result


def query(connection, schema, params, count_cap=10000):
    """ {rows, total, total_capped, live_coverage_since} for one page

    The count stops at count_cap matches: past it the total is reported as a lower bound.
    """
    where, args = _where(params)
    table = _ident(schema, EVENT_TABLE)
    columns = sql.SQL(", ").join(sql.Identifier(column) for column in COLUMNS)
    with connection.cursor(cursor_factory=extras.RealDictCursor) as cursor:
        cursor.execute(
            sql.SQL("SELECT count(*) AS total FROM (SELECT 1 FROM {}").format(table) + sql.SQL(where)
            + sql.SQL(" LIMIT %s) AS matched"),
            args + [count_cap + 1],
        )
        total = cursor.fetchone()["total"]
        capped = total > count_cap
        total = min(total, count_cap)
        cursor.execute(
            sql.SQL("SELECT {} FROM {}").format(columns, table) + sql.SQL(where) + _order(params)
            + sql.SQL(" LIMIT %s OFFSET %s"),
            args + [params.get("limit", 50), params.get("offset", 0)],
        )
        rows = [_serialize(row) for row in cursor.fetchall()]
    since = coverage_since(connection, schema)
    connection.commit()
    return {
        "rows": rows,
        "total": total,
        "total_capped": capped,
        "live_coverage_since": since.astimezone(UTC).isoformat() if since else None,
    }


def _csv_cell(value):
    if value is None:
        return ""
    if isinstance(value, datetime.datetime):
        return value.astimezone(UTC).isoformat()
    if isinstance(value, (list, dict)):
        value = json.dumps(value, sort_keys=True, default=str)
    value = str(value)
    if value.startswith(CSV_UNSAFE_PREFIXES):
        value = "'" + value
    return value


def export_csv(connection, schema, params, chunk_rows=1000):
    """ Every row matching params, in params order, as CSV text chunks (no limit / offset) """
    where, args = _where(params)
    columns = sql.SQL(", ").join(sql.Identifier(column) for column in CSV_COLUMNS)
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(CSV_COLUMNS)
    yield buffer.getvalue()
    # Server-side cursor: the result set is streamed, not loaded
    with connection.cursor(name="admin_lifecycle_audit_export") as cursor:
        cursor.itersize = chunk_rows
        cursor.execute(
            sql.SQL("SELECT {} FROM {}").format(columns, _ident(schema, EVENT_TABLE))
            + sql.SQL(where) + _order(params), args,
        )
        while True:
            rows = cursor.fetchmany(chunk_rows)
            if not rows:
                break
            buffer = io.StringIO()
            writer = csv.writer(buffer)
            for row in rows:
                writer.writerow([_csv_cell(value) for value in row])
            yield buffer.getvalue()
    connection.commit()
