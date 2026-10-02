"""Unit tests for #6788 - restoring a project backup keeps its chat templates.

Covers utils/project_restore.py:
  - chat_templates rows from the backup replace the target's in a merge restore
  - participant project_id is repointed at the target on a cross-project restore
"""
import importlib.util
import json
import pathlib
import sys
import types

import pytest


UTILS_PATH = pathlib.Path(__file__).resolve().parents[2] / "utils"
PACKAGE = "_admin_utils_6788"


def _load_restore_module():
    """Import utils/project_restore.py without a running pylon"""
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
    for name in ("project_backup", "project_restore"):
        spec = importlib.util.spec_from_file_location(
            "{}.{}".format(PACKAGE, name), UTILS_PATH / "{}.py".format(name),
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
    #
    return sys.modules["{}.project_restore".format(PACKAGE)]


pr = _load_restore_module()


SOURCE_PROJECT = 7
TARGET_PROJECT = 12
PUBLIC_PROJECT = 1

PARTICIPANTS = [
    {"id": 5, "name": "Agent", "entity_name": "application", "project_id": SOURCE_PROJECT},
    {"id": 9, "name": "Jira", "entity_name": "toolkit", "project_id": SOURCE_PROJECT},
    {"id": 3, "name": "Public agent", "entity_name": "application", "project_id": PUBLIC_PROJECT},
    {"id": 42, "name": "Some user", "entity_name": "user"},
]


class FakeCursor:
    """ Answers the catalog queries restore_safe_backup makes, records the rest """

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
        #
        if "from information_schema.tables" in lowered:
            self._result = [(table,) for table in self.connection.tables]
        elif "from information_schema.columns" in lowered and "is_nullable" in lowered:
            self._result = []
        elif "from information_schema.columns" in lowered:
            self._result = [
                (table, column)
                for table, columns in self.connection.tables.items()
                for column in columns
            ]
        elif lowered.startswith('select id, "participants"::text'):
            self._result = list(self.connection.template_rows)
        else:
            self._result = []

    def fetchall(self):
        return self._result


class FakeConnection:
    def __init__(self, template_rows=()):
        self.tables = {
            "chat_templates": {"id", "name", "participants", "is_default"},
            "applications": {"id", "name", "owner_id"},
        }
        self.template_rows = template_rows
        self.executed = []
        self.committed = False
        self.rolled_back = False

    def cursor(self):
        return FakeCursor(self)

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def statements(self):
        return [sql for sql, _ in self.executed]


def _backup(with_templates=True):
    parts = [
        "SET search_path TO \"p_7\", public;\nBEGIN;\n",
        'INSERT INTO "applications" ("id", "name", "owner_id") VALUES\n'
        "    (5, 'Agent', 7)\nON CONFLICT DO NOTHING;\n",
    ]
    if with_templates:
        parts.append(
            'INSERT INTO "chat_templates" ("id", "name", "participants", "is_default") VALUES\n'
            "    (1, 'Default', '{}', true),\n"
            "    (2, 'Other', '[]', false)\n"
            "ON CONFLICT DO NOTHING;\n".format(json.dumps(PARTICIPANTS))
        )
    parts.append("COMMIT;\n")
    text = "".join(parts)
    return lambda: iter([text])


def _restore(connection, open_chunks, **kwargs):
    return pr.restore_safe_backup(connection, open_chunks, "p_12", **kwargs)


class TestRemapProjectReferences:

    def test_source_project_entries_point_at_target(self):
        result = pr.remap_project_references(PARTICIPANTS, SOURCE_PROJECT, TARGET_PROJECT)
        assert result[0]["project_id"] == TARGET_PROJECT
        assert result[1]["project_id"] == TARGET_PROJECT

    def test_public_and_user_entries_untouched(self):
        result = pr.remap_project_references(PARTICIPANTS, SOURCE_PROJECT, TARGET_PROJECT)
        assert result[2] == PARTICIPANTS[2]
        assert result[3] == PARTICIPANTS[3]
        assert "project_id" not in result[3]

    def test_input_not_mutated(self):
        original = json.loads(json.dumps(PARTICIPANTS))
        pr.remap_project_references(PARTICIPANTS, SOURCE_PROJECT, TARGET_PROJECT)
        assert PARTICIPANTS == original

    @pytest.mark.parametrize("value", [None, {}, "x", 5])
    def test_non_list_passthrough(self, value):
        assert pr.remap_project_references(value, SOURCE_PROJECT, TARGET_PROJECT) == value


class TestChatTemplatesReplaced:

    def test_merge_restore_clears_target_templates_before_inserting(self):
        connection = FakeConnection()
        summary = _restore(connection, _backup())
        statements = connection.statements()
        #
        delete_index = statements.index('DELETE FROM "chat_templates"')
        insert_index = next(
            i for i, sql in enumerate(statements) if sql.startswith('INSERT INTO "chat_templates"')
        )
        assert delete_index < insert_index
        assert statements.count('DELETE FROM "chat_templates"') == 1
        assert summary["replaced_tables"] == ["chat_templates"]
        assert connection.committed

    def test_other_tables_keep_merge_semantics(self):
        connection = FakeConnection()
        _restore(connection, _backup())
        assert not any(sql.startswith('DELETE FROM "applications"') for sql in connection.statements())

    def test_backup_without_templates_leaves_target_alone(self):
        connection = FakeConnection()
        summary = _restore(connection, _backup(with_templates=False))
        assert not any(sql.startswith("DELETE") for sql in connection.statements())
        assert summary["replaced_tables"] == []

    def test_truncate_restore_does_not_delete_again(self):
        connection = FakeConnection()
        summary = _restore(connection, _backup(), truncate=True)
        assert not any(sql.startswith("DELETE") for sql in connection.statements())
        assert "chat_templates" in summary["truncated_tables"]
        assert summary["replaced_tables"] == []

    def test_partial_restore_of_other_tables_keeps_templates(self):
        connection = FakeConnection()
        _restore(connection, _backup(), tables=["applications"])
        assert not any(sql.startswith("DELETE") for sql in connection.statements())

    def test_dry_run_rolls_back(self):
        connection = FakeConnection()
        _restore(connection, _backup(), dry_run=True)
        assert connection.rolled_back
        assert not connection.committed


class TestCrossProjectRemap:

    def _rows(self):
        return [(1, json.dumps(PARTICIPANTS)), (2, "[]")]

    def test_participants_repointed_at_target_project(self):
        connection = FakeConnection(template_rows=self._rows())
        summary = _restore(
            connection, _backup(),
            owner_user_id=99, owner_project_id=TARGET_PROJECT, source_project_id=SOURCE_PROJECT,
        )
        updates = [
            (sql, params) for sql, params in connection.executed
            if sql.startswith('UPDATE "chat_templates"')
        ]
        assert len(updates) == 1
        params = updates[0][1]
        assert params[1] == 1
        assert json.loads(params[0]) == pr.remap_project_references(
            PARTICIPANTS, SOURCE_PROJECT, TARGET_PROJECT,
        )
        assert summary["remapped_rows"] == 1

    def test_same_project_restore_does_not_remap(self):
        connection = FakeConnection(template_rows=self._rows())
        summary = _restore(connection, _backup())
        assert not any(sql.startswith("UPDATE") for sql in connection.statements())
        assert summary["remapped_rows"] == 0

    def test_no_remap_when_templates_not_restored(self):
        connection = FakeConnection(template_rows=self._rows())
        _restore(
            connection, _backup(), tables=["applications"],
            owner_user_id=99, owner_project_id=TARGET_PROJECT, source_project_id=SOURCE_PROJECT,
        )
        assert not any(sql.startswith("UPDATE") for sql in connection.statements())
