"""Integration tests for #7506 - a merge restore of another project's backup gets fresh ids.

Source and target both number their rows from 1, so every id of the backup is
taken in the target by an unrelated entity. A merge restore must add the
backup's entities next to the target's, keep the links between them, and add
nothing when the same backup is restored again.

    cd tests && ELITEA_TEST_PG_DSN="postgresql://centry:changeme@localhost:5432/db" \\
        python run_tests.py integration/test_7506_merge_restore_remap.py

Skipped when the variable is not set.
"""
import importlib.util
import json
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
PACKAGE = "_admin_utils_7506_it"

SOURCE = "p_921"
TARGET = "p_922"
SOURCE_ID = 921
TARGET_ID = 922
RESTORER = 6

# The entity tables as elitea_core creates them, reduced to the columns that matter here
DDL = """
CREATE TABLE {s}.tags (id serial PRIMARY KEY, name varchar NOT NULL UNIQUE, data json);
CREATE TABLE {s}.applications (id serial PRIMARY KEY, name varchar NOT NULL, description varchar,
    owner_id integer NOT NULL, uuid uuid NOT NULL UNIQUE, meta jsonb NOT NULL DEFAULT '{{}}');
CREATE TABLE {s}.application_versions (id serial PRIMARY KEY,
    application_id integer NOT NULL REFERENCES {s}.applications(id),
    name varchar NOT NULL, author_id integer NOT NULL, uuid uuid NOT NULL UNIQUE,
    instructions varchar, meta jsonb NOT NULL DEFAULT '{{}}', UNIQUE (application_id, name));
CREATE TABLE {s}.application_version_tag_association (
    version_id integer REFERENCES {s}.application_versions(id),
    tag_id integer REFERENCES {s}.tags(id));
CREATE TABLE {s}.elitea_tools (id serial PRIMARY KEY, type varchar NOT NULL, name varchar,
    description varchar, settings jsonb NOT NULL DEFAULT '{{}}', author_id integer NOT NULL,
    meta jsonb NOT NULL DEFAULT '{{}}', created_at timestamp NOT NULL DEFAULT clock_timestamp());
CREATE TABLE {s}.entity_tool_mapping (id serial PRIMARY KEY,
    tool_id integer NOT NULL REFERENCES {s}.elitea_tools(id) ON DELETE CASCADE,
    entity_id integer NOT NULL, entity_version_id integer NOT NULL, entity_type varchar NOT NULL,
    selected_tools jsonb, UNIQUE (entity_version_id, tool_id, entity_type));
CREATE TABLE {s}.skills (id serial PRIMARY KEY, name varchar NOT NULL, description varchar NOT NULL,
    owner_id integer NOT NULL, author_id integer NOT NULL, uuid uuid NOT NULL UNIQUE,
    meta jsonb NOT NULL DEFAULT '{{}}');
CREATE TABLE {s}.skill_versions (id serial PRIMARY KEY,
    skill_id integer NOT NULL REFERENCES {s}.skills(id) ON DELETE CASCADE,
    name varchar NOT NULL, instructions text NOT NULL, author_id integer NOT NULL,
    uuid uuid NOT NULL UNIQUE, status varchar NOT NULL, meta jsonb NOT NULL DEFAULT '{{}}',
    UNIQUE (skill_id, name));
CREATE TABLE {s}.skill_version_tag_association (
    version_id integer REFERENCES {s}.skill_versions(id) ON DELETE CASCADE,
    tag_id integer REFERENCES {s}.tags(id) ON DELETE CASCADE);
CREATE TABLE {s}.skill_version_files (id serial PRIMARY KEY,
    skill_version_id integer NOT NULL REFERENCES {s}.skill_versions(id) ON DELETE CASCADE,
    path varchar(1024) NOT NULL, size integer NOT NULL, sha256 varchar(64) NOT NULL,
    content_type varchar(255) NOT NULL, is_text boolean NOT NULL);
CREATE TABLE {s}.entity_skill_mapping (id serial PRIMARY KEY, entity_version_id integer NOT NULL,
    entity_type varchar NOT NULL,
    skill_id integer NOT NULL REFERENCES {s}.skills(id) ON DELETE CASCADE,
    skill_version_id integer REFERENCES {s}.skill_versions(id),
    UNIQUE (entity_version_id, skill_id, entity_type));
CREATE TABLE {s}.chat_templates (id serial PRIMARY KEY, name varchar NOT NULL UNIQUE,
    participants jsonb NOT NULL DEFAULT '[]', is_default boolean NOT NULL DEFAULT false);
"""

ENTITY_TABLES = (
    "tags", "applications", "application_versions", "application_version_tag_association",
    "elitea_tools", "entity_tool_mapping", "skills", "skill_versions", "skill_version_tag_association",
    "skill_version_files", "entity_skill_mapping",
)


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
    for name in ("skill_files_backup", "project_backup", "chat_backup", "chat_restore",
                 "entity_restore", "project_restore"):
        path = UTILS_PATH / "{}.py".format(name)
        if not path.exists():
            continue
        spec = importlib.util.spec_from_file_location("{}.{}".format(PACKAGE, name), path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        modules[name] = module
    return modules


MODULES = _load_utils()
pb = MODULES["project_backup"]
pr = MODULES["project_restore"]


def _insert(cursor, schema, table, row):
    columns = list(row)
    values = [json.dumps(v) if isinstance(v, (dict, list)) else v for v in row.values()]
    cursor.execute(
        "INSERT INTO {}.{} ({}) VALUES ({}) RETURNING *".format(
            schema, table, ", ".join(columns), ", ".join(["%s"] * len(columns)),
        ),
        values,
    )
    return cursor.fetchone()[0]


def _seed_project(cursor, schema, project_id, prefix, tag):
    """ An agent with a skill (one version, one file), a toolkit, an agent-toolkit
        wrapping a second agent, a tag and a chat template listing the agent """
    ids = {}
    tag_id = _insert(cursor, schema, "tags", {"name": tag})
    for key in ("child", "main"):
        ids[key] = _insert(cursor, schema, "applications", {
            "name": "{}-{}".format(prefix, key), "owner_id": project_id, "uuid": str(uuid.uuid4()),
        })
        ids[key + "_version"] = _insert(cursor, schema, "application_versions", {
            "application_id": ids[key], "name": "base", "author_id": 3, "uuid": str(uuid.uuid4()),
            "instructions": "{} {}".format(prefix, key),
        })
        cursor.execute(
            "UPDATE {}.applications SET meta = jsonb_build_object('default_version_id', %s::int)"
            " WHERE id = %s".format(schema), (ids[key + "_version"], ids[key]),
        )
    _insert(cursor, schema, "application_version_tag_association",
            {"version_id": ids["main_version"], "tag_id": tag_id})
    #
    ids["toolkit"] = _insert(cursor, schema, "elitea_tools", {
        "type": "github", "name": "{}-github".format(prefix), "settings": {"repository": prefix}, "author_id": 3,
    })
    ids["agent_toolkit"] = _insert(cursor, schema, "elitea_tools", {
        "type": "application", "name": "base", "author_id": 3,
        "settings": {"application_id": ids["child"], "application_version_id": ids["child_version"]},
    })
    for tool in ("toolkit", "agent_toolkit"):
        _insert(cursor, schema, "entity_tool_mapping", {
            "tool_id": ids[tool], "entity_id": ids["main"], "entity_version_id": ids["main_version"],
            "entity_type": "agent",
        })
    #
    ids["skill"] = _insert(cursor, schema, "skills", {
        "name": "{}-skill".format(prefix), "description": prefix, "owner_id": project_id, "author_id": 3,
        "uuid": str(uuid.uuid4()),
    })
    ids["skill_version"] = _insert(cursor, schema, "skill_versions", {
        "skill_id": ids["skill"], "name": "base", "instructions": "{} instructions".format(prefix),
        "author_id": 3, "uuid": str(uuid.uuid4()), "status": "published",
    })
    cursor.execute(
        "UPDATE {}.skills SET meta = jsonb_build_object('default_version_id', %s::int)"
        " WHERE id = %s".format(schema), (ids["skill_version"], ids["skill"]),
    )
    _insert(cursor, schema, "skill_version_tag_association",
            {"version_id": ids["skill_version"], "tag_id": tag_id})
    _insert(cursor, schema, "skill_version_files", {
        "skill_version_id": ids["skill_version"], "path": "{}/guide.md".format(prefix), "size": 1,
        "sha256": prefix.ljust(64, "0"), "content_type": "text/markdown", "is_text": True,
    })
    _insert(cursor, schema, "entity_skill_mapping", {
        "entity_version_id": ids["main_version"], "entity_type": "agent",
        "skill_id": ids["skill"], "skill_version_id": ids["skill_version"],
    })
    _insert(cursor, schema, "chat_templates", {
        "name": "{}-template".format(prefix),
        "participants": [{"id": ids["main"], "project_id": project_id, "entity_name": "application"}],
    })
    return ids


@pytest.fixture(scope="module")
def database():
    name = "elitea_test_7506_{}".format(uuid.uuid4().hex[:8])
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


def _connect(database, populated):
    connection = psycopg2.connect(**database)
    with connection.cursor() as cursor:
        for schema in (SOURCE, TARGET):
            cursor.execute("DROP SCHEMA IF EXISTS {} CASCADE".format(schema))
            cursor.execute("CREATE SCHEMA {}".format(schema))
            cursor.execute(DDL.format(s=schema))
        if populated:
            # Two unrelated agents first: every id of the source is taken in the target
            for index in range(2):
                _insert(cursor, TARGET, "applications", {
                    "name": "t-extra-{}".format(index), "owner_id": TARGET_ID, "uuid": str(uuid.uuid4()),
                })
            _seed_project(cursor, TARGET, TARGET_ID, "t", "dev")
        _seed_project(cursor, SOURCE, SOURCE_ID, "s", "prod")
    connection.commit()
    return connection


@pytest.fixture()
def connection(database):
    connection = _connect(database, populated=True)
    yield connection
    connection.close()


@pytest.fixture()
def empty_target(database):
    connection = _connect(database, populated=False)
    yield connection
    connection.close()


def _backup(connection):
    text = "".join(pb.iter_project_backup_sql(connection, SOURCE_ID, SOURCE, "Source"))
    connection.rollback()
    return text


def _restore(connection, text, truncate=False):
    return pr.restore_safe_backup(
        connection, open_chunks=lambda: iter([text]), schema=TARGET, truncate=truncate,
        denied_tables=pr.SAFE_RESTORE_DENIED_TABLES, owner_user_id=RESTORER, owner_project_id=TARGET_ID,
        source_project_id=SOURCE_ID, project_id=TARGET_ID,
    )


def _rows(connection, query, params=None):
    with connection.cursor() as cursor:
        cursor.execute(query, params)
        rows = cursor.fetchall()
    connection.rollback()
    return rows


def _snapshot(connection, schema=TARGET):
    """ table -> set of rows as text, for comparing whole tables """
    return {
        table: {row[0] for row in _rows(connection, "SELECT t::text FROM {}.{} t".format(schema, table))}
        for table in ENTITY_TABLES
    }


def _graph(connection, prefix):
    """ The links of the agent '<prefix>-main' as names, resolved through the target's ids """
    s = TARGET
    main = _rows(connection, "SELECT id, meta FROM {}.applications WHERE name = %s".format(s),
                 ("{}-main".format(prefix),))
    assert len(main) == 1, "agent {}-main is present once".format(prefix)
    main_id, main_meta = main[0]
    version = _rows(connection, "SELECT id, instructions FROM {}.application_versions"
                                " WHERE application_id = %s".format(s), (main_id,))
    assert len(version) == 1
    version_id = version[0][0]
    return {
        "version": version[0][1],
        "default_version": main_meta.get("default_version_id") == version_id,
        "tags": sorted(row[0] for row in _rows(connection, (
            "SELECT t.name FROM {s}.application_version_tag_association a JOIN {s}.tags t ON t.id = a.tag_id"
            " WHERE a.version_id = %s").format(s=s), (version_id,))),
        "skills": _rows(connection, (
            "SELECT k.name, v.instructions, f.path, v.skill_id = k.id,"
            " (k.meta->>'default_version_id')::int = v.id"
            " FROM {s}.entity_skill_mapping m JOIN {s}.skills k ON k.id = m.skill_id"
            " JOIN {s}.skill_versions v ON v.id = m.skill_version_id"
            " JOIN {s}.skill_version_files f ON f.skill_version_id = v.id"
            " WHERE m.entity_version_id = %s AND m.entity_type = 'agent'").format(s=s), (version_id,)),
        "skill_tags": sorted(row[0] for row in _rows(connection, (
            "SELECT t.name FROM {s}.entity_skill_mapping m"
            " JOIN {s}.skill_version_tag_association a ON a.version_id = m.skill_version_id"
            " JOIN {s}.tags t ON t.id = a.tag_id WHERE m.entity_version_id = %s").format(s=s), (version_id,))),
        "toolkits": sorted(_rows(connection, (
            "SELECT t.type, t.name, c.name, cv.instructions FROM {s}.entity_tool_mapping m"
            " JOIN {s}.elitea_tools t ON t.id = m.tool_id"
            " LEFT JOIN {s}.applications c ON c.id = (t.settings->>'application_id')::int"
            " LEFT JOIN {s}.application_versions cv ON cv.id = (t.settings->>'application_version_id')::int"
            " WHERE m.entity_version_id = %s AND m.entity_id = %s AND m.entity_type = 'agent'").format(s=s),
            (version_id, main_id))),
        "template": [
            [item["id"] == main_id and item["project_id"] == TARGET_ID for item in row[0]]
            for row in _rows(connection, "SELECT participants FROM {}.chat_templates WHERE name = %s".format(s),
                             ("{}-template".format(prefix),))
        ],
    }


def _expected_graph(prefix, tag):
    return {
        "version": "{} main".format(prefix),
        "default_version": True,
        "tags": [tag],
        "skills": [("{}-skill".format(prefix), "{} instructions".format(prefix),
                    "{}/guide.md".format(prefix), True, True)],
        "skill_tags": [tag],
        "toolkits": sorted([
            ("application", "base", "{}-child".format(prefix), "{} child".format(prefix)),
            ("github", "{}-github".format(prefix), None, None),
        ]),
        "template": [[True]],
    }


def _seed_ids(connection):
    s = TARGET
    ids = {table: [row[0] for row in _rows(connection, "SELECT id FROM {}.{}".format(s, table))]
           for table in ("applications", "application_versions", "skills", "skill_versions")}
    ids["children"] = {
        table: _rows(connection, "SELECT count(*) FROM {}.{}".format(s, table))[0][0]
        for table in ("skill_versions", "skill_version_files", "skill_version_tag_association",
                      "application_version_tag_association", "entity_skill_mapping", "entity_tool_mapping")
    }
    return ids


def test_merge_restore_leaves_the_target_entities_unchanged(connection):  # AC-1
    before = _snapshot(connection)
    target_graph = _graph(connection, "t")
    _restore(connection, _backup(connection))
    after = _snapshot(connection)
    for table in ENTITY_TABLES:
        assert before[table] <= after[table], "{}: a target row changed or disappeared".format(table)
    # Chat templates are project settings the backup replaces (#6788), not merged content
    assert _graph(connection, "t") == dict(target_graph, template=[]) \
        == dict(_expected_graph("t", "dev"), template=[])


def test_merge_restore_attaches_nothing_of_the_backup_to_target_entities(connection):  # AC-1
    target_ids = _seed_ids(connection)
    _restore(connection, _backup(connection))
    s = TARGET
    assert _rows(connection, "SELECT count(*) FROM {}.application_versions WHERE application_id = ANY(%s)"
                 .format(s), (target_ids["applications"],))[0][0] == len(target_ids["application_versions"])
    for table, column, parent in (
            ("skill_versions", "skill_id", "skills"),
            ("skill_version_files", "skill_version_id", "skill_versions"),
            ("skill_version_tag_association", "version_id", "skill_versions"),
            ("application_version_tag_association", "version_id", "application_versions"),
            ("entity_skill_mapping", "entity_version_id", "application_versions"),
            ("entity_tool_mapping", "entity_version_id", "application_versions"),
    ):
        count = _rows(connection, "SELECT count(*) FROM {}.{} WHERE {} = ANY(%s)".format(s, table, column),
                      (target_ids[parent],))[0][0]
        assert count == target_ids["children"][table], "{} rows of the backup hang under target {}".format(
            table, parent)


@pytest.mark.parametrize("fixture", ["connection", "empty_target"], ids=["populated target", "empty target"])
def test_merge_restore_adds_the_backup_with_its_links(request, fixture):  # AC-2, AC-4
    connection = request.getfixturevalue(fixture)
    _restore(connection, _backup(connection))
    assert _graph(connection, "s") == _expected_graph("s", "prod")
    # The restored skill belongs to the target project and the restoring user
    assert _rows(connection, "SELECT owner_id, author_id FROM {}.skills WHERE name = 's-skill'".format(TARGET)) \
        == [(TARGET_ID, RESTORER)]


def test_merge_restore_keeps_the_target_sequences_ahead(connection):  # AC-1
    _restore(connection, _backup(connection))
    with connection.cursor() as cursor:
        for table in ("applications", "skills", "elitea_tools"):
            cursor.execute("SELECT max(id) FROM {}.{}".format(TARGET, table))
            highest = cursor.fetchone()[0]
            cursor.execute("SELECT nextval(pg_get_serial_sequence('{}.{}', 'id'))".format(TARGET, table))
            assert cursor.fetchone()[0] > highest, table
    connection.rollback()


def test_restoring_the_same_backup_twice_adds_nothing(connection):  # AC-3
    text = _backup(connection)
    _restore(connection, text)
    once = _snapshot(connection)
    summary = _restore(connection, text)
    assert _snapshot(connection) == once
    entities = summary["entities"]
    assert entities["applications"] == dict(entities["applications"], restored=0, skipped=2)
    assert entities["skills"] == dict(entities["skills"], restored=0, skipped=1)
    assert entities["elitea_tools"] == dict(entities["elitea_tools"], restored=0, skipped=2)
    assert _graph(connection, "s") == _expected_graph("s", "prod")


def test_replace_restore_keeps_the_backup_ids(connection):  # AC-6
    source = _snapshot(connection, SOURCE)
    _restore(connection, _backup(connection), truncate=True)
    ids = {table: sorted(row[0] for row in _rows(connection, "SELECT id FROM {}.{}".format(TARGET, table)))
           for table in ("applications", "application_versions", "skills", "skill_versions", "elitea_tools")}
    assert ids == {table: sorted(row[0] for row in _rows(connection, "SELECT id FROM {}.{}".format(SOURCE, table)))
                   for table in ids}
    assert len(_snapshot(connection)["entity_skill_mapping"]) == len(source["entity_skill_mapping"])
    assert _graph(connection, "s") == _expected_graph("s", "prod")


def test_a_failed_merge_restore_commits_nothing(connection, monkeypatch):  # AC-7
    before = _snapshot(connection)

    def explode(*args, **kwargs):
        raise RuntimeError("late failure")
    monkeypatch.setattr(pr, "_remap_project_reference_columns", explode)
    with pytest.raises(RuntimeError, match="late failure"):
        _restore(connection, _backup(connection))
    assert _snapshot(connection) == before


def _restore_partial(connection, text, tables):
    return pr.restore_safe_backup(
        connection, open_chunks=lambda: iter([text]), schema=TARGET, tables=tables,
        denied_tables=pr.SAFE_RESTORE_DENIED_TABLES, owner_user_id=RESTORER, owner_project_id=TARGET_ID,
        source_project_id=SOURCE_ID, project_id=TARGET_ID,
    )


def test_a_partial_restore_never_hangs_rows_under_target_parents_holding_their_id(connection):  # review F1
    target_ids = _seed_ids(connection)
    summary = _restore_partial(connection, _backup(connection), ["application_versions", "entity_tool_mapping"])
    s = TARGET
    assert _rows(connection, "SELECT count(*) FROM {}.application_versions WHERE application_id = ANY(%s)"
                 .format(s), (target_ids["applications"],))[0][0] == len(target_ids["application_versions"])
    assert _rows(connection, "SELECT count(*) FROM {}.entity_tool_mapping".format(s))[0][0] \
        == target_ids["children"]["entity_tool_mapping"]
    assert summary["entities"]["application_versions"]["restored"] == 0


def test_template_entries_follow_entities_restored_into_their_own_project(database):  # review F5
    connection = _connect(database, populated=False)
    try:
        with connection.cursor() as cursor:
            # The source project lost its agents since the backup; its template still lists one
            text = _backup(connection)
            cursor.execute("TRUNCATE {s}.applications, {s}.elitea_tools, {s}.skills, {s}.tags CASCADE".format(
                s=SOURCE))
            _insert(cursor, SOURCE, "applications", {
                "name": "unrelated", "owner_id": SOURCE_ID, "uuid": str(uuid.uuid4())})
        connection.commit()
        pr.restore_safe_backup(
            connection, open_chunks=lambda: iter([text]), schema=SOURCE,
            denied_tables=pr.SAFE_RESTORE_DENIED_TABLES, project_id=SOURCE_ID,
            chat_context={"target_project_id": SOURCE_ID},
        )
        main = _rows(connection, "SELECT id FROM {}.applications WHERE name = 's-main'".format(SOURCE))[0][0]
        participants = _rows(connection, "SELECT participants FROM {}.chat_templates WHERE name = 's-template'"
                             .format(SOURCE))[0][0]
        assert participants == [{"id": main, "project_id": SOURCE_ID, "entity_name": "application"}]
    finally:
        connection.close()


def test_a_toolkit_with_a_redacted_secret_is_recognised_on_the_second_restore(connection):  # review F2
    with connection.cursor() as cursor:
        cursor.execute(
            "UPDATE {}.elitea_tools SET settings = settings || '{{\"api_key\": \"sk-abcdefghijklmnopqrstuvwxyz0123\"}}'"
            " WHERE type = 'github'".format(SOURCE))
    connection.commit()
    text = _backup(connection)
    assert "sk-abcdefghijklmnopqrstuvwxyz0123" not in text
    _restore(connection, text)
    # The restored toolkit holds the redacted value; the user re-enters the secret
    with connection.cursor() as cursor:
        cursor.execute("UPDATE {}.elitea_tools SET settings = settings || '{{\"api_key\": \"real\"}}'"
                       " WHERE name = 's-github'".format(TARGET))
    connection.commit()
    summary = _restore(connection, text)
    assert summary["entities"]["elitea_tools"] == dict(summary["entities"]["elitea_tools"], restored=0, skipped=2)
    assert _rows(connection, "SELECT count(*) FROM {}.elitea_tools WHERE name = 's-github'".format(TARGET)) == [(1,)]

