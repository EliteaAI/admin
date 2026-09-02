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


def rewrite_owner_columns(statement, replacements):
    """ Point the owner columns of an INSERT at their new values

    The statement has already passed _is_literal_insert_tail, so every value is
    a literal and every tuple is flat: the slots belonging to the owner columns
    can be found by counting commas and replaced in place.
    """
    match = INSERT_RE.match(statement)
    if match is None:
        return statement
    #
    tail = statement[match.end():]
    tail_match = INSERT_TAIL_RE.match(tail)
    if tail_match is None:
        return statement
    #
    targets = {
        index: str(int(replacements[name]))
        for index, name in enumerate(_insert_column_names(tail, tail_match))
        if name in replacements
    }
    if not targets:
        return statement
    #
    values = tail_match.group(1)
    body_end = INSERT_SUFFIX_RE.search(values).start()
    body = values[:body_end]
    #
    spans = []
    index = 0
    length = len(body)
    depth = 0
    slot = 0
    slot_start = 0
    #
    while index < length:
        token = VALUE_TOKEN_RE.match(body, index)
        if token is None:
            return statement
        #
        text = token.group(0)
        #
        if text == "(":
            depth += 1
            slot = 0
            slot_start = token.end()
        elif depth == 1 and text in (",", ")"):
            if slot in targets:
                spans.append((slot_start, token.start(), targets[slot]))
            if text == ",":
                slot += 1
                slot_start = token.end()
            else:
                depth -= 1
        #
        index = token.end()
    #
    if not spans:
        return statement
    #
    pieces = []
    cursor = 0
    #
    for start, end, replacement in spans:
        pieces.append(body[cursor:start])
        pieces.append(replacement)
        cursor = end
    pieces.append(body[cursor:])
    #
    return "{}{}{}{}".format(
        statement[:match.end()], tail[:tail_match.start(1)],
        "".join(pieces), values[body_end:],
    )


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
            if kind == STATEMENT_INSERT:
                replacements = owner_replacements(table, owner_user_id, owner_project_id)
                if replacements:
                    statement = rewrite_owner_columns(statement, replacements)
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


def run_psql(  # pylint: disable=R0913,R0914
        open_chunks, schema, host, port, user, password, database,
        dry_run=False, extra_args=(),
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
                    process.stdin.write(chunk)
                    written += len(chunk)
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
        "return_code": return_code,
        "stdout": stdout[-4000:],
        "stderr": stderr[-4000:],
    }
