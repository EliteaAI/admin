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

""" Project restore: apply a backup produced by project_backup """

import re

import psycopg2  # pylint: disable=E0401

from pylon.core.tools import log  # pylint: disable=E0611,E0401

from .project_backup import SAFE_MODE_EXCLUDED_TABLES


KIND_SAFE = "safe"
KIND_PG_DUMP = "pg_dump"

HEADER_MARKER = "-- ELITEA project backup"
PG_DUMP_MARKERS = (
    "-- PostgreSQL database dump",
    "SET statement_timeout",
    "pg_dump version",
)

HEADER_SCAN_BYTES = 262144
MAX_STATEMENT_BYTES = 67108864

HEADER_LINE_RE = re.compile(r"^--\s*([a-z_]+):\s*(.*?)\s*$")

INSERT_RE = re.compile(
    r'^insert\s+into\s+(?:"([^"]+)"|([a-z_][0-9a-z_$]*))', re.IGNORECASE | re.DOTALL
)
# Anchors the exact shape emitted by project_backup._iter_table_sql's setval
# line: SELECT setval(pg_get_serial_sequence('"table"', 'col'),
# GREATEST((SELECT COALESCE(MAX("col"), 0) FROM "table"), 1), true);
# Groups: 1/4 = table (sequence arg / FROM target), 2/3 = column (sequence
# arg / MAX() target) - classify_statement checks both pairs agree so the
# subquery can't be pointed at a different table/column than declared.
SETVAL_RE = re.compile(
    r"^select\s+setval\s*\(\s*pg_get_serial_sequence\s*\(\s*'\"([^'\"]+)\"'\s*,"
    r"\s*'([^']+)'\s*\)\s*,\s*greatest\s*\(\s*\(\s*select\s+coalesce\s*\(\s*max\s*\("
    r"\"([^'\"]+)\"\s*\)\s*,\s*0\s*\)\s+from\s+\"([^'\"]+)\"\s*\)\s*,\s*1\s*\)\s*,"
    r"\s*true\s*\)\s*;?\s*$",
    re.IGNORECASE | re.DOTALL,
)
TRANSACTION_RE = re.compile(
    r"^(begin|commit|rollback|start\s+transaction|end)\b", re.IGNORECASE
)
SET_RE = re.compile(r"^set\s+", re.IGNORECASE)
# The tail of a generated INSERT: a double-quoted column list, VALUES, then the
# value tuples (project_backup._make_insert), optionally ON CONFLICT DO NOTHING.
INSERT_TAIL_RE = re.compile(
    r'^\s*\(\s*"(?:[^"]|"")*"(?:\s*,\s*"(?:[^"]|"")*")*\s*\)\s*values\b(.*)$',
    re.IGNORECASE | re.DOTALL,
)
INSERT_SUFFIX_RE = re.compile(
    r"(?:\s*on\s+conflict\s+do\s+nothing)?\s*;?\s*$", re.IGNORECASE
)
# Value grammar of project_backup._literal (psycopg2 mogrify output): tuple
# punctuation, NULL/TRUE/FALSE, numbers, quoted strings ('' doubling, E''
# backslash escapes) and ::type casts. Identifiers, operators and function
# calls have no token here, so a subquery can not be expressed at all.
VALUE_TOKEN_RE = re.compile(
    r"\s+"
    r"|[(),]"
    r"|null|true|false"
    r"|[+-]?(?:\d+\.?\d*|\.\d+)(?:e[+-]?\d+)?"
    r"|e'(?:[^'\\]|''|\\.)*'"
    r"|'(?:[^']|'')*'"
    r"|::\s*[a-z_][0-9a-z_]*(?:\s+[a-z_][0-9a-z_]*)*(?:\s*\[\s*\])*",
    re.IGNORECASE,
)
NULL_VALUE_RE = re.compile(r"\bnull\b", re.IGNORECASE)
# A value slot holding no value, with or without the cast psycopg2 may append
NULL_SLOT_RE = re.compile(r"^null(?:\s*::[^,)]*)?$", re.IGNORECASE)

# The schema a pg_dump artifact rebuilds, in order of confidence
CREATE_SCHEMA_RE = re.compile(
    r'^\s*create\s+schema\s+(?:if\s+not\s+exists\s+)?(?:"([^"]+)"|([a-z_][0-9a-z_$]*))',
    re.IGNORECASE | re.MULTILINE,
)
SCHEMA_COMMENT_RE = re.compile(
    r'^--\s*Name:\s*"?([^";]+?)"?;\s*Type:\s*SCHEMA\b', re.IGNORECASE | re.MULTILINE,
)
QUALIFIED_TABLE_RE = re.compile(
    r'^\s*create\s+table\s+(?:"([^"]+)"|([a-z_][0-9a-z_$]*))\s*\.',
    re.IGNORECASE | re.MULTILINE,
)

# Lines a pg_dump preamble is made of, and the SET among them whose parameter
# has to be known to the target server
PREAMBLE_SET_RE = re.compile(rb"^\s*set\s+([a-z_][0-9a-z_.]*)\s*(?:=|to\s)", re.IGNORECASE)
PREAMBLE_LINE_RE = re.compile(
    rb"^\s*(?:--.*|\\[a-z].*|set\s.*|select\s+pg_catalog\.set_config\s*\(.*)?\s*$",
    re.IGNORECASE,
)

STATEMENT_INSERT = "insert"
STATEMENT_SETVAL = "setval"
STATEMENT_TRANSACTION = "transaction"
STATEMENT_SET = "set"
STATEMENT_UNSUPPORTED = "unsupported"

# A safe backup never carries these tables, so an artifact that does was not
# produced by the exporter. Restoring role / role_permission / user_role rows
# would hand out permissions in the target project, so the whole restore is
# refused instead of skipping the table.
SAFE_RESTORE_DENIED_TABLES = frozenset(SAFE_MODE_EXCLUDED_TABLES)

# Rewritten to the restoring user when an artifact from another project is
# applied, so restored entities are not attributed to that project's users
USER_OWNER_COLUMNS = ("author_id", "owner_id")

# Tables where owner_id holds the owning project instead of a user (see
# elitea_core.utils.application_utils: "owner_id": project_id). Pointing it at
# a user there makes every restored row look foreign to its own project.
PROJECT_OWNER_COLUMN = "owner_id"
PROJECT_OWNED_TABLES = frozenset(("applications", "prompts", "skills"))

# Value used for a column the target requires but the backup does not carry
# (added NOT NULL by a migration that gave it no database default). Types with
# no unambiguous empty value are absent on purpose - inventing one there would
# be a guess, so the restore stops and names the column instead.
FILL_LITERALS = {
    "boolean": "false",
    "smallint": "0",
    "integer": "0",
    "bigint": "0",
    "numeric": "0",
    "decimal": "0",
    "real": "0",
    "double precision": "0",
    "text": "''",
    "character varying": "''",
    "character": "''",
    "json": "'{}'",
    "jsonb": "'{}'",
    "date": "CURRENT_DATE",
    "timestamp without time zone": "CURRENT_TIMESTAMP",
    "timestamp with time zone": "CURRENT_TIMESTAMP",
}


def _quote(identifier):
    return '"{}"'.format(str(identifier).replace('"', '""'))


def _is_literal_insert_tail(tail):
    """ True if everything after 'INSERT INTO <table>' is a quoted column list
        plus VALUES tuples built from literals only - no identifiers, function
        calls or subqueries, so no cross-schema read can be smuggled in """
    match = INSERT_TAIL_RE.match(tail)
    if match is None:
        return False
    #
    values = match.group(1)
    values = values[:INSERT_SUFFIX_RE.search(values).start()]
    #
    index = 0
    length = len(values)
    depth = 0
    tuples = 0
    #
    while index < length:
        token = VALUE_TOKEN_RE.match(values, index)
        if token is None:
            return False
        #
        if token.group(0) == "(":
            depth += 1
            if depth > 1:
                return False
        elif token.group(0) == ")":
            depth -= 1
            if depth < 0:
                return False
            tuples += 1
        #
        index = token.end()
    #
    return depth == 0 and tuples > 0


def _insert_column_names(tail, tail_match):
    """ Column names of an INSERT tail, in order """
    return [
        name.replace('""', '"')
        for name in re.findall(r'"((?:[^"]|"")*)"', tail[:tail_match.start(1)])
    ]


def insert_column_names(statement):
    """ Column names an INSERT statement writes, in order, or None """
    match = INSERT_RE.match(statement)
    if match is None:
        return None
    #
    tail = statement[match.end():]
    tail_match = INSERT_TAIL_RE.match(tail)
    if tail_match is None:
        return None
    #
    return _insert_column_names(tail, tail_match)


def owner_replacements(table, user_id=None, project_id=None):
    """ The value each owner column of `table` has to be rewritten to """
    replacements = {}
    #
    if user_id is not None:
        for column in USER_OWNER_COLUMNS:
            replacements[column] = user_id
    #
    if table in PROJECT_OWNED_TABLES:
        replacements.pop(PROJECT_OWNER_COLUMN, None)
        if project_id is not None:
            replacements[PROJECT_OWNER_COLUMN] = project_id
    #
    return replacements


def _value_tuples(body):
    """ Per VALUES tuple, its (start, end) span and the span of each value in it """
    tuples = []
    index = 0
    length = len(body)
    depth = 0
    current = None
    slot_start = 0
    #
    while index < length:
        token = VALUE_TOKEN_RE.match(body, index)
        if token is None:
            return None
        #
        text = token.group(0)
        #
        if text == "(":
            if depth:
                return None
            depth = 1
            current = [token.start(), None, []]
            slot_start = token.end()
        elif depth == 1 and text in (",", ")"):
            current[2].append((slot_start, token.start()))
            if text == ",":
                slot_start = token.end()
            else:
                current[1] = token.end()
                tuples.append(current)
                current = None
                depth = 0
        #
        index = token.end()
    #
    if depth or current is not None:
        return None
    #
    return tuples


def rewrite_insert(statement, replacements=None, missing_columns=(), required_types=None):
    """ Rebuild an INSERT for a schema that drifted from the one backed up

    Owner columns are repointed, columns the target does not have are dropped,
    and columns the target requires get an empty value where the backup has
    none: appended when the column is absent from the statement, substituted
    when it is present but NULL. Both drifts come from migrations - one dropped
    a column the backup still has, another added a NOT NULL one it does not.

    The statement has already passed _is_literal_insert_tail, so every value is
    a literal and every tuple is flat: the slots belonging to a column can be
    found by counting commas, and each tuple is rebuilt from the literals that
    stay. Returns (statement, dropped_values, filled_columns), counting the
    non-NULL values that were dropped and naming the columns that were filled.
    """
    replacements = replacements or {}
    missing = frozenset(missing_columns)
    required = required_types or {}
    #
    match = INSERT_RE.match(statement)
    if match is None:
        return statement, 0, ()
    #
    tail = statement[match.end():]
    tail_match = INSERT_TAIL_RE.match(tail)
    if tail_match is None:
        return statement, 0, ()
    #
    table = match.group(1) or match.group(2)
    names = _insert_column_names(tail, tail_match)
    #
    dropped_slots = {index for index, name in enumerate(names) if name in missing}
    targets = {
        index: str(int(replacements[name]))
        for index, name in enumerate(names)
        if name in replacements and index not in dropped_slots
    }
    #
    # A column the statement does not list can only be filled, so its literal is
    # resolved now; one it does list is only filled where its value is NULL, so
    # an unfillable type stays harmless until such a value actually shows up.
    added = [
        (name, fill_literal(table, name, data_type))
        for name, data_type in required.items()
        if name not in names
    ]
    fillable = {
        index: (name, required[name])
        for index, name in enumerate(names)
        if name in required and index not in dropped_slots and index not in targets
    }
    #
    if not dropped_slots and not targets and not added and not fillable:
        return statement, 0, ()
    #
    kept = [name for index, name in enumerate(names) if index not in dropped_slots]
    if not kept:
        raise ValueError(
            "no column of {} exists in the target schema".format(table)
        )
    #
    values = tail_match.group(1)
    body_end = INSERT_SUFFIX_RE.search(values).start()
    body = values[:body_end]
    #
    tuples = _value_tuples(body)
    if tuples is None:
        return statement, 0, ()
    #
    pieces = []
    cursor = 0
    dropped_values = 0
    filled = [name for name, _ in added]
    #
    for start, end, slots in tuples:
        if len(slots) != len(names):
            return statement, 0, ()
        #
        rebuilt = []
        #
        for index, (slot_start, slot_end) in enumerate(slots):
            text = body[slot_start:slot_end].strip()
            #
            if index in dropped_slots:
                if not NULL_SLOT_RE.match(text):
                    dropped_values += 1
                continue
            #
            if index in fillable and NULL_SLOT_RE.match(text):
                name, data_type = fillable[index]
                text = fill_literal(table, name, data_type)
                if name not in filled:
                    filled.append(name)
            #
            rebuilt.append(targets.get(index, text))
        #
        rebuilt.extend(value for _, value in added)
        #
        pieces.append(body[cursor:start])
        pieces.append("({})".format(", ".join(rebuilt)))
        cursor = end
    #
    pieces.append(body[cursor:])
    #
    return "{} ({}) VALUES{}{}".format(
        statement[:match.end()],
        ", ".join(_quote(name) for name in kept + [name for name, _ in added]),
        "".join(pieces), values[body_end:],
    ), dropped_values, filled


def rewrite_owner_columns(statement, replacements):
    """ Point the owner columns of an INSERT at their new values """
    return rewrite_insert(statement, replacements)[0]


def detect_artifact_kind(head):
    """ Tell a safe (INSERT-only) backup from a raw pg_dump """
    if any(marker in head for marker in PG_DUMP_MARKERS):
        return KIND_PG_DUMP
    if HEADER_MARKER in head:
        return KIND_SAFE
    if "INSERT INTO" in head.upper():
        return KIND_SAFE
    return None


def parse_header(head):
    """ Read the '-- key: value' block a safe backup starts with """
    result = {}
    #
    for line in head.splitlines():
        line = line.strip()
        if not line.startswith("--"):
            if result:
                break
            continue
        #
        match = HEADER_LINE_RE.match(line)
        if match is None:
            continue
        #
        key, value = match.group(1), match.group(2)
        if key in ("project_id", "project_name", "schema", "mode", "generated_at"):
            result.setdefault(key, value)
    #
    if "project_id" in result:
        try:
            result["project_id"] = int(result["project_id"])
        except (TypeError, ValueError):
            pass
    #
    return result


def iter_statements(chunks):  # pylint: disable=R0912,R0915
    """ Split a stream of SQL text into executable statements, comments stripped """
    code = []
    state = "normal"
    string_escapes = False
    depth = 0
    tag = ""
    pending = ""
    #
    for chunk in chunks:
        data = pending + chunk
        pending = ""
        index = 0
        length = len(data)
        #
        while index < length:
            char = data[index]
            #
            if state == "normal":
                two = data[index:index + 2]
                #
                if two == "--":
                    state = "line_comment"
                    index += 2
                    continue
                #
                if two == "/*":
                    state = "block_comment"
                    depth = 1
                    index += 2
                    continue
                #
                if char == "-" and index + 1 >= length:
                    pending = data[index:]
                    index = length
                    continue
                #
                if char == "/" and index + 1 >= length:
                    pending = data[index:]
                    index = length
                    continue
                #
                if char == "$":
                    match = re.match(r"\$[0-9a-zA-Z_]*\$", data[index:])
                    if match is not None:
                        tag = match.group(0)
                        code.append(tag)
                        state = "dollar"
                        index += len(tag)
                        continue
                    if length - index < 64 and "\n" not in data[index:]:
                        pending = data[index:]
                        index = length
                        continue
                #
                if char == "'":
                    previous = "".join(code[-1:])
                    string_escapes = previous.lower().endswith("e")
                    state = "string"
                    code.append(char)
                    index += 1
                    continue
                #
                if char == '"':
                    state = "identifier"
                    code.append(char)
                    index += 1
                    continue
                #
                if char == ";":
                    statement = "".join(code).strip()
                    code = []
                    index += 1
                    if statement:
                        yield statement
                    continue
                #
                code.append(char)
                index += 1
                continue
            #
            if state == "line_comment":
                newline = data.find("\n", index)
                if newline < 0:
                    index = length
                else:
                    code.append("\n")
                    index = newline + 1
                    state = "normal"
                continue
            #
            if state == "block_comment":
                two = data[index:index + 2]
                if two == "*/":
                    depth -= 1
                    index += 2
                    if depth <= 0:
                        state = "normal"
                        code.append(" ")
                    continue
                if two == "/*":
                    depth += 1
                    index += 2
                    continue
                if index + 1 >= length:
                    pending = data[index:]
                    index = length
                    continue
                index += 1
                continue
            #
            if state == "string":
                if string_escapes and char == "\\":
                    if index + 1 >= length:
                        pending = data[index:]
                        index = length
                        continue
                    code.append(data[index:index + 2])
                    index += 2
                    continue
                #
                if char == "'":
                    if index + 1 >= length:
                        pending = data[index:]
                        index = length
                        continue
                    if data[index + 1] == "'":
                        code.append("''")
                        index += 2
                        continue
                    code.append(char)
                    state = "normal"
                    index += 1
                    continue
                #
                code.append(char)
                index += 1
                continue
            #
            if state == "identifier":
                if char == '"':
                    if index + 1 >= length:
                        pending = data[index:]
                        index = length
                        continue
                    if data[index + 1] == '"':
                        code.append('""')
                        index += 2
                        continue
                    code.append(char)
                    state = "normal"
                    index += 1
                    continue
                #
                code.append(char)
                index += 1
                continue
            #
            if state == "dollar":
                closing = data.find(tag, index)
                if closing < 0:
                    keep = max(index, length - len(tag))
                    code.append(data[index:keep])
                    pending = data[keep:]
                    index = length
                    continue
                code.append(data[index:closing + len(tag)])
                index = closing + len(tag)
                state = "normal"
                continue
        #
        if sum(len(part) for part in code) > MAX_STATEMENT_BYTES:
            raise ValueError("Statement exceeds the size limit")
    #
    statement = "".join(code).strip()
    if statement:
        yield statement


def classify_statement(statement):
    """ Return (kind, table) for a statement of a safe backup """
    if TRANSACTION_RE.match(statement):
        return STATEMENT_TRANSACTION, None
    #
    match = INSERT_RE.match(statement)
    if match is not None:
        if not _is_literal_insert_tail(statement[match.end():]):
            return STATEMENT_UNSUPPORTED, None
        return STATEMENT_INSERT, match.group(1) or match.group(2)
    #
    match = SETVAL_RE.match(statement)
    if match is not None:
        table, column, max_column, from_table = match.groups()
        if table == from_table and column == max_column:
            return STATEMENT_SETVAL, table
        return STATEMENT_UNSUPPORTED, None
    #
    if SET_RE.match(statement):
        return STATEMENT_SET, None
    #
    return STATEMENT_UNSUPPORTED, None


def _dbapi_connection(raw_connection):
    """ Unwrap a SQLAlchemy pool connection down to the psycopg2 one """
    for attribute in ("driver_connection", "dbapi_connection", "connection"):
        candidate = getattr(raw_connection, attribute, None)
        if candidate is not None and hasattr(candidate, "cursor"):
            return candidate
    return raw_connection


def list_schema_tables(cursor, schema):
    """ Base tables present in a schema """
    cursor.execute(
        "select table_name from information_schema.tables"
        " where table_schema = %s and table_type = 'BASE TABLE'",
        (schema,),
    )
    return {row[0] for row in cursor.fetchall()}


def schema_columns(cursor, schema):
    """ table -> set of its column names """
    cursor.execute(
        "select table_name, column_name from information_schema.columns"
        " where table_schema = %s",
        (schema,),
    )
    #
    columns = {}
    for table, column in cursor.fetchall():
        columns.setdefault(table, set()).add(column)
    return columns


def required_columns(cursor, schema):
    """ table -> {column: data type} for columns a row can not omit

    NOT NULL, no database default and not generated: a backup taken before the
    migration that added such a column carries no value for it, and leaving it
    out fails the INSERT.
    """
    cursor.execute(
        "select table_name, column_name, data_type from information_schema.columns"
        " where table_schema = %s and is_nullable = 'NO' and column_default is null"
        " and is_identity = 'NO' and is_generated = 'NEVER'",
        (schema,),
    )
    #
    columns = {}
    for table, column, data_type in cursor.fetchall():
        columns.setdefault(table, {})[column] = data_type
    return columns


def fill_literal(table, column, data_type):
    """ The empty value to give a required column the backup has no value for """
    literal = FILL_LITERALS.get(str(data_type).lower())
    #
    if literal is None:
        raise ValueError(
            "the target schema requires {}.{} ({}), this backup carries no value for "
            "it and there is no obvious empty one; give the column a database default "
            "and restore again".format(table, column, data_type)
        )
    #
    return literal


def server_settings(cursor):
    """ Configuration parameters the target server knows, lowercased """
    cursor.execute("select name from pg_settings")
    return {str(row[0]).lower() for row in cursor.fetchall()}


def foreign_key_parents(cursor, schema):
    """ table -> set of tables it references """
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
    #
    parents = {}
    for child, parent in cursor.fetchall():
        if child != parent:
            parents.setdefault(child, set()).add(parent)
    return parents


def expand_with_parents(tables, parents):
    """ Add the FK ancestors of the requested tables """
    result = set(tables)
    queue = list(tables)
    #
    while queue:
        for parent in parents.get(queue.pop(), ()):
            if parent not in result:
                result.add(parent)
                queue.append(parent)
    #
    return result


def scan_backup_tables(open_chunks):
    """ Tables an artifact carries statements for """
    tables = set()
    #
    for statement in iter_statements(open_chunks()):
        _, table = classify_statement(statement)
        if table:
            tables.add(table)
    #
    return tables


def _record_dropped(summary, schema, table, columns, values=0):
    """ Note the columns a table lost to schema drift, warning once per table """
    if table not in summary["dropped_columns"]:
        log.warning(
            "project_restore: %s.%s does not exist in %s, dropping it from the restore",
            table, ", ".join(columns), schema,
        )
    #
    recorded = summary["dropped_columns"].setdefault(table, [])
    for column in columns:
        if column not in recorded:
            recorded.append(column)
    #
    summary["dropped_values"] += values


def _record_filled(summary, schema, table, columns):
    """ Note the required columns the backup had no value for """
    if table not in summary["filled_columns"]:
        log.warning(
            "project_restore: %s requires %s.%s, which this backup has no value for;"
            " restoring it empty", schema, table, ", ".join(columns),
        )
    #
    recorded = summary["filled_columns"].setdefault(table, [])
    for column in columns:
        if column not in recorded:
            recorded.append(column)


def restore_safe_backup(  # pylint: disable=R0912,R0913,R0914,R0915
        raw_connection, open_chunks, schema,
        tables=None, include_parents=False, truncate=False, dry_run=False,
        denied_tables=(), owner_user_id=None, owner_project_id=None,
):
    """ Apply a safe (INSERT-only) backup to a schema, return a summary """
    dbapi_connection = _dbapi_connection(raw_connection)
    requested = {table.strip() for table in (tables or ()) if table.strip()}
    denied = frozenset(denied_tables)
    #
    blocked = sorted(requested.intersection(denied))
    if blocked:
        raise ValueError(
            "Tables not allowed in a safe restore: {}".format(", ".join(blocked))
        )
    #
    with dbapi_connection.cursor() as cursor:
        existing = list_schema_tables(cursor, schema)
        if not existing:
            raise ValueError("Schema {} has no tables".format(schema))
        #
        columns_by_table = schema_columns(cursor, schema)
        required_by_table = required_columns(cursor, schema)
        #
        if requested and include_parents:
            requested = expand_with_parents(requested, foreign_key_parents(cursor, schema))
            requested = requested.difference(denied)
    #
    unknown = sorted(requested.difference(existing))
    if unknown:
        raise ValueError("Tables not present in {}: {}".format(schema, ", ".join(unknown)))
    #
    summary = {
        "target_schema": schema,
        "partial": bool(requested),
        "requested_tables": sorted(requested),
        "dry_run": bool(dry_run),
        "truncated_tables": [],
        "truncate_cascade": False,
        "applied_tables": [],
        "rows": {},
        "total_rows": 0,
        "statements": 0,
        "skipped_tables": [],
        "dropped_columns": {},
        "dropped_values": 0,
        "filled_columns": {},
    }
    #
    truncate_targets = []
    if truncate:
        if requested:
            truncate_targets = sorted(requested)
        else:
            truncate_targets = sorted(
                scan_backup_tables(open_chunks).intersection(existing).difference(denied)
            )
    #
    seen_tables = set()
    skipped_tables = set()
    #
    cursor = dbapi_connection.cursor()
    #
    try:
        cursor.execute("SET LOCAL search_path TO {}, public".format(_quote(schema)))
        #
        if truncate_targets:
            cursor.execute(
                "TRUNCATE {} RESTART IDENTITY CASCADE".format(
                    ", ".join(_quote(table) for table in truncate_targets)
                )
            )
            summary["truncated_tables"] = truncate_targets
            summary["truncate_cascade"] = True
        #
        for statement in iter_statements(open_chunks()):
            kind, table = classify_statement(statement)
            #
            if kind in (STATEMENT_TRANSACTION, STATEMENT_SET):
                continue
            #
            if kind == STATEMENT_UNSUPPORTED:
                raise ValueError(
                    "Unsupported statement in backup file: {}".format(
                        " ".join(statement.split())[:160]
                    )
                )
            #
            if table in denied:
                raise ValueError(
                    "table not allowed in safe restore: {}".format(table)
                )
            #
            if table is None or table not in existing:
                skipped_tables.add(table or "?")
                continue
            #
            if requested and table not in requested:
                skipped_tables.add(table)
                continue
            #
            # A backup taken before a migration carries columns the target no
            # longer has; they are dropped instead of failing the whole restore
            known_columns = columns_by_table.get(table, set())
            #
            if kind == STATEMENT_INSERT:
                names = insert_column_names(statement) or ()
                missing = [name for name in names if name not in known_columns]
                replacements = owner_replacements(table, owner_user_id, owner_project_id)
                # The other direction of the same drift: a column the target
                # requires but this backup has no value for gets an empty one
                required = required_by_table.get(table, {})
                if required and not NULL_VALUE_RE.search(statement):
                    # No NULL anywhere, so only an omitted column lacks a value
                    required = {
                        name: data_type for name, data_type in required.items()
                        if name not in names
                    }
                #
                if missing or replacements or required:
                    statement, dropped_values, filled = rewrite_insert(
                        statement, replacements, missing, required,
                    )
                    if missing:
                        _record_dropped(summary, schema, table, missing, dropped_values)
                    if filled:
                        _record_filled(summary, schema, table, filled)
            #
            if kind == STATEMENT_SETVAL:
                # pg_get_serial_sequence() errors out on an unknown column
                column = SETVAL_RE.match(statement).group(2)
                if column not in known_columns:
                    _record_dropped(summary, schema, table, [column])
                    continue
            #
            seen_tables.add(table)
            #
            try:
                cursor.execute(statement)
            except psycopg2.Error as exc:
                raise ValueError(
                    "{} failed on {}: {}".format(
                        kind, table, str(getattr(exc, "pgerror", None) or exc).strip(),
                    )
                ) from exc
            #
            summary["statements"] += 1
            #
            if kind == STATEMENT_INSERT and cursor.rowcount and cursor.rowcount > 0:
                summary["rows"][table] = summary["rows"].get(table, 0) + cursor.rowcount
                summary["total_rows"] += cursor.rowcount
        #
        summary["applied_tables"] = sorted(seen_tables)
        summary["skipped_tables"] = sorted(skipped_tables)
        #
        if dry_run:
            dbapi_connection.rollback()
        else:
            dbapi_connection.commit()
    except Exception:
        dbapi_connection.rollback()
        raise
    finally:
        cursor.close()
    #
    return summary


def pg_dump_schema(head):
    """ The schema a pg_dump artifact recreates, or None

    A plain pg_dump carries its own CREATE SCHEMA and fully qualified names, so
    it can only ever rebuild the schema it was taken from.
    """
    for pattern in (CREATE_SCHEMA_RE, SCHEMA_COMMENT_RE, QUALIFIED_TABLE_RE):
        match = pattern.search(head)
        if match is None:
            continue
        #
        for value in match.groups():
            if value:
                return value.strip()
    #
    return None


def filter_unknown_settings(open_chunks, known_settings):
    """ Comment out preamble SETs the target server does not know

    pg_dump writes the client's own defaults into the artifact preamble, so a
    dump taken with newer client tools carries parameters an older server has
    never heard of (transaction_timeout, added in 17) - and under
    --single-transaction with ON_ERROR_STOP that kills the whole restore.

    Only the preamble is rewritten: filtering stops at the first line that is
    not blank, a comment, a psql meta command, a SET or a set_config() call, so
    COPY data and function bodies pass through byte for byte. Returns the
    wrapped opener and the list the dropped names are collected into.
    """
    dropped = []
    #
    def opener():  # pylint: disable=R0912
        in_preamble = True
        pending = b""
        #
        for chunk in open_chunks():
            if isinstance(chunk, str):
                chunk = chunk.encode("utf-8")
            #
            if not in_preamble:
                yield chunk
                continue
            #
            data = pending + chunk
            pending = b""
            #
            while in_preamble:
                newline = data.find(b"\n")
                if newline < 0:
                    pending = data
                    data = b""
                    break
                #
                line = data[:newline + 1]
                data = data[newline + 1:]
                #
                match = PREAMBLE_SET_RE.match(line)
                if match is not None:
                    name = match.group(1).decode("utf-8", "replace").lower()
                    if name in known_settings:
                        yield line
                        continue
                    if name not in dropped:
                        dropped.append(name)
                    yield b"-- unknown to the target server, dropped: " + line
                    continue
                #
                if PREAMBLE_LINE_RE.match(line):
                    yield line
                    continue
                #
                in_preamble = False
                data = line + data
            #
            if not in_preamble and data:
                yield data
        #
        if pending:
            yield pending
    #
    return opener, dropped


def run_psql(  # pylint: disable=R0913,R0914
        open_chunks, schema, host, port, user, password, database,
        dry_run=False, extra_args=(), known_settings=None,
):
    """ Feed a pg_dump artifact to psql inside a single transaction """
    import os  # pylint: disable=C0415
    import tempfile  # pylint: disable=C0415
    import subprocess  # pylint: disable=C0415
    #
    command = [
        "psql",
        "--host={}".format(host),
        "--port={}".format(port),
        "--username={}".format(user),
        "--dbname={}".format(database),
        "--quiet",
        "--no-psqlrc",
        "--single-transaction",
        "--variable=ON_ERROR_STOP=1",
    ]
    command.extend(extra_args)
    #
    dropped_settings = []
    if known_settings:
        open_chunks, dropped_settings = filter_unknown_settings(open_chunks, known_settings)
    #
    prologue = "SET search_path TO {}, public;\n".format(_quote(schema))
    epilogue = "\n\\echo restore rolled back (dry run)\nROLLBACK;\n" if dry_run else ""
    #
    environment = dict(os.environ)
    environment["PGPASSWORD"] = password or ""
    #
    # NOTE: psql output goes to spool files, not pipes. We write the whole
    # artifact to stdin before reading anything back, so a pipe would let psql
    # fill its ~64K stdout/stderr buffer (NOTICE storm, ON_ERROR_STOP abort)
    # and block on write while we block on write - a deadlock that, under
    # gevent, parks the request greenlet forever.
    #
    with tempfile.TemporaryFile() as output_spool, tempfile.TemporaryFile() as error_spool:
        process = subprocess.Popen(  # pylint: disable=R1732
            command,
            stdin=subprocess.PIPE,
            stdout=output_spool,
            stderr=error_spool,
            env=environment,
        )
        #
        written = 0
        #
        try:
            try:
                process.stdin.write(prologue.encode("utf-8"))
                #
                for chunk in open_chunks():
                    if isinstance(chunk, str):
                        chunk = chunk.encode("utf-8")
                    # counted before the write: a psql that already died leaves
                    # bytes_sent showing what was attempted, not zero
                    written += len(chunk)
                    process.stdin.write(chunk)
                #
                if epilogue:
                    process.stdin.write(epilogue.encode("utf-8"))
            except BrokenPipeError:
                log.error("psql closed its input early")
            finally:
                try:
                    process.stdin.close()
                except BrokenPipeError:
                    pass
            #
            return_code = process.wait()
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
        #
        output_spool.seek(0)
        stdout = output_spool.read().decode("utf-8", "replace")
        error_spool.seek(0)
        stderr = error_spool.read().decode("utf-8", "replace")
    #
    return {
        "target_schema": schema,
        "dry_run": bool(dry_run),
        "bytes_sent": written,
        "dropped_settings": dropped_settings,
        "return_code": return_code,
        "stdout": stdout[-4000:],
        "stderr": stderr[-4000:],
    }
