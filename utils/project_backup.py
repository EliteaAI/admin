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

""" Project backup: SQL dump of a single project schema """

import re
import json
import datetime

import psycopg2  # pylint: disable=E0401
import psycopg2.extras  # pylint: disable=E0401

from pylon.core.tools import log  # pylint: disable=E0611,E0401


psycopg2.extras.register_uuid()

REDACTED = "***REDACTED***"

#
# Tables never exported in "safe" mode
#
SAFE_MODE_EXCLUDED_TABLES = {
    #
    # Access control: these rows grant roles and permissions
    #
    "role": "project roles",
    "role_permission": "role permissions",
    "user_role": "user role assignments",
    #
    # Credentials, endpoints and storage of the source project
    #
    "configuration": "integration endpoints and credentials",
    "artifacts": "storage objects of the source project",
    #
    # Conversations: personal content, tied to the users who took part
    #
    "chat_conversations": "conversation history",
    "chat_conversation_folders": "conversation history",
    "chat_conversation_share_tokens": "share tokens and password hashes",
    "chat_conversation_summaries": "derived conversation context",
    "chat_message_group": "conversation history",
    "chat_message_items": "conversation history",
    "chat_message_trace_step": "execution traces",
    "chat_messages_text": "conversation history",
    "chat_messages_attachment": "conversation history",
    "chat_messages_canvas": "conversation history",
    "chat_messages_context": "conversation context payloads",
    "chat_canvas_versions": "conversation history",
    "chat_canvas_version_authors": "conversation history",
    "chat_participants": "participants of the source project",
    "chat_participant_mapping": "participants of the source project",
    "chat_selected_conversations": "per-user conversation state",
    #
    # Per-user state of the source project
    #
    "social_user_module_settings": "per-user settings",
    "social_folder_items": "per-user folder layout",
    #
    # Platform / run state, not project content
    #
    "moderation_state": "platform publish/moderation workflow state",
    "eval_run": "evaluation run output",
    "eval_result": "evaluation run output",
    "eval_human_score": "evaluation run output",
    #
    # Legacy
    #
    "alita_tools": "legacy, superseded by elitea_tools",
    "chat_messages": "legacy, superseded by chat_message_group/chat_message_items",
}

#
# Column / JSON key names whose string values are redacted in "safe" mode
#
SENSITIVE_KEY_PARTS = (
    "token", "secret", "password", "passwd", "passphrase",
    "api_key", "apikey", "api-key", "access_key", "accesskey",
    "private_key", "privatekey", "credential", "authorization",
    "auth_token", "auth-token", "cookie", "connection_string", "signature",
)

#
# Value patterns redacted regardless of the key they are stored under
#
SENSITIVE_VALUE_RE = re.compile(
    r"(ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|glpat-|xox[baprse]-|"
    r"AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|"
    r"sk-[A-Za-z0-9_-]{16,}|sk_live_|rk_live_|"
    r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})"
)
PRIVATE_KEY_MARKER = "PRIVATE KEY-----"

SECRET_REF_RE = re.compile(r"^\s*\{\{\s*secret\.[^}]+\}\}\s*$")

JSON_DATA_TYPES = ("json", "jsonb")
TEXT_DATA_TYPES = ("text", "character varying", "character", "citext")

DEFAULT_CHUNK_SIZE = 500
ROWS_PER_STATEMENT = 100


def is_sensitive_name(name):
    """ Whether a column / JSON key name looks like it holds a secret """
    lowered = str(name).lower()
    return any(part in lowered for part in SENSITIVE_KEY_PARTS)


def is_secret_ref(value):
    """ Whether a value is a vault reference and therefore safe to keep """
    return isinstance(value, str) and bool(SECRET_REF_RE.match(value))


def looks_like_secret_value(value):
    """ Whether a string value looks like a credential regardless of its key """
    if not isinstance(value, str) or not value or len(value) > 100000:
        return False
    if PRIVATE_KEY_MARKER in value:
        return True
    return any(SENSITIVE_VALUE_RE.search(part) for part in value.split())


def scrub_value(value, key=None):
    """ Recursively redact secrets in a JSON-like value """
    if isinstance(value, dict):
        return {k: scrub_value(v, k) for k, v in value.items()}
    #
    if isinstance(value, (list, tuple)):
        return [scrub_value(item, key) for item in value]
    #
    if isinstance(value, str) and value:
        if is_secret_ref(value):
            return value
        if key is not None and is_sensitive_name(key) and not value.isdigit():
            return REDACTED
        if looks_like_secret_value(value):
            return REDACTED
    #
    return value


class _Redactor:
    """ Per-table redaction rules derived from the live schema """

    def __init__(self, columns, enabled=True):
        self.enabled = enabled
        self.hits = 0
        #
        self.json_columns = set()
        self.sensitive_json_columns = set()
        self.text_columns = set()
        self.sensitive_columns = set()
        self.name_column = None
        self.value_is_json = False
        #
        if not enabled:
            return
        #
        names = [name for name, _ in columns]
        #
        for name, data_type in columns:
            if data_type in JSON_DATA_TYPES:
                if is_sensitive_name(name):
                    self.sensitive_json_columns.add(name)
                else:
                    self.json_columns.add(name)
                if name == "value":
                    self.value_is_json = True
            elif is_sensitive_name(name):
                self.sensitive_columns.add(name)
            elif data_type in TEXT_DATA_TYPES:
                self.text_columns.add(name)
        #
        # Name/value pairs (e.g. application_variables): the value is only
        # sensitive when the accompanying name says so
        #
        if "value" in names:
            for candidate in ("name", "key", "variable_name"):
                if candidate in names:
                    self.name_column = candidate
                    break

    def apply(self, row):
        """ Redact a row (mapping of column -> value) in place """
        if not self.enabled:
            return row
        #
        for column in self.sensitive_columns:
            value = row.get(column)
            if value is None or value == "" or is_secret_ref(value):
                continue
            row[column] = REDACTED
            self.hits += 1
        #
        for column in self.sensitive_json_columns:
            value = row.get(column)
            if value is None or value in ("", "null"):
                continue
            row[column] = json.dumps(REDACTED)
            self.hits += 1
        #
        for column in self.json_columns:
            value = row.get(column)
            if value is None:
                continue
            scrubbed = self._scrub_json(value)
            if scrubbed != value:
                row[column] = scrubbed
                self.hits += 1
        #
        for column in self.text_columns:
            value = row.get(column)
            if looks_like_secret_value(value):
                row[column] = REDACTED
                self.hits += 1
        #
        if self.name_column is not None:
            value = row.get("value")
            redacted = json.dumps(REDACTED) if self.value_is_json else REDACTED
            if value not in (None, "") and not is_secret_ref(value) \
                    and is_sensitive_name(row.get(self.name_column) or ""):
                if row["value"] != redacted:
                    self.hits += 1
                row["value"] = redacted
        #
        return row

    @staticmethod
    def _scrub_json(value):
        """ Redact a JSON column carried as text, keeping 'null' distinct from NULL """
        if not isinstance(value, str):
            return scrub_value(value, None)
        #
        try:
            decoded = json.loads(value)
        except (TypeError, ValueError):
            return REDACTED if looks_like_secret_value(value) else value
        #
        scrubbed = scrub_value(decoded, None)
        if scrubbed == decoded:
            return value
        #
        return json.dumps(scrubbed)


def _dbapi_connection(raw_connection):
    """ Unwrap a SQLAlchemy pool connection down to the psycopg2 one """
    for attribute in ("driver_connection", "dbapi_connection", "connection"):
        candidate = getattr(raw_connection, attribute, None)
        if candidate is not None and hasattr(candidate, "cursor"):
            return candidate
    return raw_connection


def _quote(identifier):
    return '"{}"'.format(str(identifier).replace('"', '""'))


def list_tables(cursor, schema):
    """ Base tables of a schema """
    cursor.execute(
        "select table_name from information_schema.tables"
        " where table_schema = %s and table_type = 'BASE TABLE'"
        " order by table_name",
        (schema,),
    )
    return [row[0] for row in cursor.fetchall()]


def _list_columns(cursor, schema, table):
    cursor.execute(
        "select column_name, data_type from information_schema.columns"
        " where table_schema = %s and table_name = %s"
        " order by ordinal_position",
        (schema, table),
    )
    return [(row[0], row[1]) for row in cursor.fetchall()]


def _list_sequence_columns(cursor, schema, table):
    cursor.execute(
        "select column_name from information_schema.columns"
        " where table_schema = %s and table_name = %s"
        " and (is_identity = 'YES' or column_default like 'nextval(%%')",
        (schema, table),
    )
    return [row[0] for row in cursor.fetchall()]


def _foreign_key_edges(cursor, schema):
    cursor.execute(
        "select child.relname, parent.relname"
        " from pg_constraint con"
        " join pg_class child on child.oid = con.conrelid"
        " join pg_class parent on parent.oid = con.confrelid"
        " join pg_namespace child_ns on child_ns.oid = child.relnamespace"
        " join pg_namespace parent_ns on parent_ns.oid = parent.relnamespace"
        " where con.contype = 'f'"
        " and child_ns.nspname = %s and parent_ns.nspname = %s",
        (schema, schema),
    )
    return [(row[0], row[1]) for row in cursor.fetchall()]


def _self_reference_columns(cursor, schema):
    """ Map self-referencing tables to the columns their own FKs point at """
    cursor.execute(
        "select child.relname, attr.attname"
        " from pg_constraint con"
        " join pg_class child on child.oid = con.conrelid"
        " join pg_namespace child_ns on child_ns.oid = child.relnamespace"
        " cross join unnest(con.confkey) as ref(attnum)"
        " join pg_attribute attr"
        " on attr.attrelid = con.confrelid and attr.attnum = ref.attnum"
        " where con.contype = 'f'"
        " and con.conrelid = con.confrelid"
        " and child_ns.nspname = %s"
        " order by child.relname, attr.attnum",
        (schema,),
    )
    #
    result = {}
    for table, column in cursor.fetchall():
        columns = result.setdefault(table, [])
        if column not in columns:
            columns.append(column)
    return result


def order_tables(tables, edges):
    """ Order tables so that parents are inserted before their children """
    table_set = set(tables)
    parents = {table: set() for table in tables}
    children = {table: set() for table in tables}
    #
    for child, parent in edges:
        if child not in table_set or parent not in table_set or child == parent:
            continue
        parents[child].add(parent)
        children[parent].add(child)
    #
    ready = sorted(table for table in tables if not parents[table])
    ordered = []
    #
    while ready:
        table = ready.pop(0)
        ordered.append(table)
        for child in sorted(children[table]):
            parents[child].discard(table)
            if not parents[child]:
                ready.append(child)
        ready.sort()
    #
    # Cyclic remainder (self-referencing chains) goes last, alphabetically
    #
    ordered.extend(sorted(table_set.difference(ordered)))
    return ordered


def _literal(mogrify_cursor, value):
    if isinstance(value, (dict, list)):
        value = psycopg2.extras.Json(value, dumps=json.dumps)
    return mogrify_cursor.mogrify("%s", (value,)).decode("utf-8", "replace")


def _iter_table_sql(  # pylint: disable=R0913,R0914
        dbapi_connection, mogrify_cursor, schema, table, columns, redactor,
        chunk_size=DEFAULT_CHUNK_SIZE, order_by=(),
):
    """ Yield INSERT statements for a single table """
    column_names = [name for name, _ in columns]
    json_columns = {name for name, data_type in columns if data_type in JSON_DATA_TYPES}
    column_list = ", ".join(_quote(name) for name in column_names)
    #
    # JSON columns are read as text: psycopg2 decodes them to Python objects,
    # which turns a stored 'null' into None and then into SQL NULL - breaking
    # NOT NULL json columns on restore.
    #
    select_list = ", ".join(
        "{}::text".format(_quote(name)) if name in json_columns else _quote(name)
        for name in column_names
    )
    #
    cursor = dbapi_connection.cursor(
        name="project_backup_{}".format(re.sub(r"[^0-9a-zA-Z_]", "_", table)),
    )
    cursor.itersize = chunk_size
    #
    row_count = 0
    buffer = []
    #
    # Rows are split across several INSERT statements and FK checks run at the end
    # of each one, so a self-referencing table must emit parents first. Ordering by
    # the referenced (identity/serial) column does that: a row can only point at an
    # already existing row, which therefore has a lower value.
    #
    query = "select {} from {}.{}".format(select_list, _quote(schema), _quote(table))
    if order_by:
        query += " order by {}".format(
            ", ".join("{} asc".format(_quote(name)) for name in order_by)
        )
    #
    try:
        cursor.execute(query)
        #
        for row in cursor:
            values = redactor.apply(dict(zip(column_names, row)))
            buffer.append(
                "({})".format(
                    ", ".join(
                        _literal(mogrify_cursor, values[name])
                        for name in column_names
                    )
                )
            )
            row_count += 1
            #
            if len(buffer) >= ROWS_PER_STATEMENT:
                yield _make_insert(table, column_list, buffer)
                buffer = []
    finally:
        cursor.close()
    #
    if buffer:
        yield _make_insert(table, column_list, buffer)
    #
    yield row_count


def _make_insert(table, column_list, buffer):
    return "INSERT INTO {} ({}) VALUES\n    {}\nON CONFLICT DO NOTHING;\n".format(
        _quote(table), column_list, ",\n    ".join(buffer),
    )


def iter_project_backup_sql(  # pylint: disable=R0913,R0914,R0915
        raw_connection, project_id, schema, project_name=None,
        safe_mode=True, extra_excluded_tables=(), chunk_size=DEFAULT_CHUNK_SIZE,
):
    """ Yield the project backup as a stream of SQL text chunks """
    dbapi_connection = _dbapi_connection(raw_connection)
    #
    excluded = {}
    if safe_mode:
        excluded.update(SAFE_MODE_EXCLUDED_TABLES)
    for table in extra_excluded_tables:
        table = table.strip()
        if table:
            excluded[table] = "excluded by request"
    #
    with dbapi_connection.cursor() as cursor:
        all_tables = list_tables(cursor, schema)
        if not all_tables:
            raise ValueError("Schema {} has no tables".format(schema))
        #
        tables = [table for table in all_tables if table not in excluded]
        tables = order_tables(tables, _foreign_key_edges(cursor, schema))
        #
        columns = {table: _list_columns(cursor, schema, table) for table in tables}
        sequences = {
            table: _list_sequence_columns(cursor, schema, table) for table in tables
        }
        self_references = _self_reference_columns(cursor, schema)
    #
    generated_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    skipped = sorted(table for table in all_tables if table in excluded)
    #
    yield _header(
        project_id, project_name, schema, generated_at, safe_mode, tables, skipped, excluded,
    )
    #
    counts = {}
    redaction_hits = 0
    #
    with dbapi_connection.cursor() as mogrify_cursor:
        for table in tables:
            table_columns = columns[table]
            if not table_columns:
                continue
            #
            redactor = _Redactor(table_columns, enabled=safe_mode)
            yield "--\n-- {}\n--\n".format(table)
            #
            for item in _iter_table_sql(
                    dbapi_connection, mogrify_cursor, schema, table,
                    table_columns, redactor, chunk_size,
                    self_references.get(table, ()),
            ):
                if isinstance(item, int):
                    counts[table] = item
                else:
                    yield item
            #
            redaction_hits += redactor.hits
            #
            if counts.get(table):
                for column in sequences[table]:
                    yield (
                        "SELECT setval(pg_get_serial_sequence('\"{}\"', '{}'),"
                        " GREATEST((SELECT COALESCE(MAX({}), 0) FROM {}), 1), true);\n"
                    ).format(table, column, _quote(column), _quote(table))
            #
            yield "\n"
    #
    yield _footer(counts, redaction_hits)


def _header(  # pylint: disable=R0913
        project_id, project_name, schema, generated_at, safe_mode, tables, skipped, excluded,
):
    lines = [
        "--",
        "-- ELITEA project backup",
        "--",
        "-- project_id:   {}".format(project_id),
        "-- project_name: {}".format(project_name or "-"),
        "-- schema:       {}".format(schema),
        "-- mode:         {}".format("safe" if safe_mode else "full"),
        "-- generated_at: {}".format(generated_at),
        "--",
    ]
    #
    if safe_mode:
        lines += [
            "-- Sensitive values are replaced with '{}'.".format(REDACTED),
            "-- Vault references ({{secret.NAME}}) are kept as-is; the secret values",
            "-- themselves are NOT part of this backup and must be re-entered.",
            "--",
            "-- Skipped tables:",
        ]
        for table in skipped:
            lines.append("--   {} - {}".format(table, excluded[table]))
        if not skipped:
            lines.append("--   (none)")
        lines.append("--")
    #
    lines += [
        "-- Data only: this backup contains no DDL. Create the target schema first",
        "-- (an empty project), then adjust the search_path below and run:",
        "--   psql -d <database> -f <this file>",
        "--",
        "-- Insert order ({} tables): {}".format(len(tables), ", ".join(tables)),
        "--",
        "",
        "SET client_encoding TO 'UTF8';",
        "SET search_path TO {}, public;".format(_quote(schema)),
        "",
        "BEGIN;",
        "",
    ]
    return "\n".join(lines)


def _footer(counts, redaction_hits):
    lines = ["COMMIT;", "", "--", "-- Exported rows:"]
    #
    total = 0
    for table in sorted(counts):
        total += counts[table]
        if counts[table]:
            lines.append("--   {}: {}".format(table, counts[table]))
    #
    lines += [
        "--   total: {}".format(total),
        "-- Redacted values: {}".format(redaction_hits),
        "--",
        "",
    ]
    return "\n".join(lines)


def iter_pg_dump(  # pylint: disable=R0913
        schema, host, port, user, password, database, extra_args=(),
):
    """ Yield raw pg_dump output for a single schema """
    import os  # pylint: disable=C0415
    import tempfile  # pylint: disable=C0415
    import subprocess  # pylint: disable=C0415
    #
    command = [
        "pg_dump",
        "--host={}".format(host),
        "--port={}".format(port),
        "--username={}".format(user),
        "--dbname={}".format(database),
        "--schema={}".format(schema),
        "--no-owner",
        "--no-privileges",
        "--format=plain",
    ]
    command.extend(extra_args)
    #
    environment = dict(os.environ)
    environment["PGPASSWORD"] = password or ""
    #
    # NOTE: stderr goes to a spool file, not a pipe: it is only read after
    # stdout reaches EOF, and an undrained pipe would block pg_dump once its
    # ~64K kernel buffer fills up.
    #
    with tempfile.TemporaryFile() as error_spool:
        process = subprocess.Popen(  # pylint: disable=R1732
            command,
            stdout=subprocess.PIPE,
            stderr=error_spool,
            env=environment,
        )
        #
        try:
            while True:
                chunk = process.stdout.read(65536)
                if not chunk:
                    break
                yield chunk
            #
            process.stdout.close()
            return_code = process.wait()
            #
            if return_code != 0:
                error_spool.seek(0)
                error = error_spool.read().decode("utf-8", "replace").strip()
                log.error("pg_dump failed (%s): %s", return_code, error)
                yield "\n-- pg_dump failed with code {}\n".format(return_code).encode("utf-8")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            if not process.stdout.closed:
                process.stdout.close()
