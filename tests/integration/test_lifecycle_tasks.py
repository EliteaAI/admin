"""Integration tests for tasks/lifecycle_tasks.py - imports the real module with stubs."""
import re
import sys
import types
import json

import pytest


class StubLog:
    def info(self, *a, **kw): pass
    def debug(self, *a, **kw): pass
    def warning(self, *a, **kw): pass
    def error(self, *a, **kw): pass
    def exception(self, *a, **kw): pass
    def critical(self, *a, **kw): pass


PROJECT_USER_EMAIL_TEMPLATE = 'system_user_{}@centry.user'
PROJECT_PERSONAL_NAME_TEMPLATE = 'project_user_{user_id}'


def real_is_system_user(email: str) -> bool:
    """Faithful copy of plugins.projects.rpc.poc.is_system_user."""
    system_user_email = PROJECT_USER_EMAIL_TEMPLATE.format(r'(\d+)')
    match = re.match(rf"^{system_user_email}$", email or "")
    return bool(match)


@pytest.fixture(scope="module")
def lifecycle_tasks(plugin_root):
    """Load the real tasks/lifecycle_tasks.py module with cross-plugin imports stubbed."""
    import tools  # noqa: F401 (stubbed by run_tests.py)

    tools.context = types.ModuleType('tools.context')
    tools.log = StubLog()

    sys.modules['tools.context'] = tools.context
    sys.modules['tools.log'] = tools.log

    plugins_pkg = types.ModuleType('plugins')
    plugins_projects_pkg = types.ModuleType('plugins.projects')
    plugins_projects_constants = types.ModuleType('plugins.projects.constants')
    plugins_projects_constants.PROJECT_PERSONAL_NAME_TEMPLATE = PROJECT_PERSONAL_NAME_TEMPLATE
    plugins_projects_rpc_pkg = types.ModuleType('plugins.projects.rpc')
    plugins_projects_rpc_poc = types.ModuleType('plugins.projects.rpc.poc')
    plugins_projects_rpc_poc.is_system_user = real_is_system_user

    sys.modules['plugins'] = plugins_pkg
    sys.modules['plugins.projects'] = plugins_projects_pkg
    sys.modules['plugins.projects.constants'] = plugins_projects_constants
    sys.modules['plugins.projects.rpc'] = plugins_projects_rpc_pkg
    sys.modules['plugins.projects.rpc.poc'] = plugins_projects_rpc_poc

    fixtures_dir = plugin_root / "tests" / "fixtures"
    sys.path.insert(0, str(fixtures_dir))
    try:
        from helpers import load_module_with_stubs
    finally:
        sys.path.remove(str(fixtures_dir))

    module_path = plugin_root / "tasks" / "lifecycle_tasks.py"
    module = load_module_with_stubs(module_path, "lifecycle_tasks_under_test")
    return module


class FakeCall:
    """Dispatches attribute access to a dict of stub functions, mimicking rpc_manager.call.*"""

    def __init__(self, funcs):
        self._funcs = funcs

    def __getattr__(self, name):
        try:
            return self._funcs[name]
        except KeyError:
            raise AttributeError(name)  # noqa: B904


class FakeRpcManager:
    def __init__(self, funcs):
        self.call = FakeCall(funcs)

    def timeout(self, _seconds):
        return self.call


class FakeQuery:
    def __init__(self, projects_db, model):
        self._projects_db = projects_db
        self._model = model
        self._project_id = None

    def where(self, cond):
        _kind, _field, value = cond
        self._project_id = value
        return self

    def first(self):
        if self._project_id not in self._projects_db:
            return None
        return FakeProjectRow(self._projects_db, self._project_id)


class FakeProjectRow:
    def __init__(self, projects_db, project_id):
        self._projects_db = projects_db
        self._project_id = project_id

    @property
    def suspended(self):
        return self._projects_db[self._project_id]["suspended"]

    @suspended.setter
    def suspended(self, value):
        self._projects_db[self._project_id]["suspended"] = value


class FakeSession:
    def __init__(self, projects_db):
        self._projects_db = projects_db

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def query(self, model):
        return FakeQuery(self._projects_db, model)

    def commit(self):
        pass


@pytest.fixture
def task_env(lifecycle_tasks):
    """
        Wire fresh fake RPC/auth/db/model stubs into the already-loaded lifecycle_tasks
        module so the two task functions can be exercised end to end.
    """
    projects = {}  # project_id -> dict (id, name, owner_id, suspended)
    users = {}  # user_id -> dict (id, email, suspended)
    personal_project_by_user = {}  # user_id -> project_id
    deleted_project_ids = []
    removed_from_project = []

    def project_get_by_id(project_id):
        project = projects.get(project_id)
        return dict(project) if project else None

    def project_list(filter_=None):  # pylint: disable=unused-argument
        return [dict(project) for project in projects.values()]

    def projects_get_personal_project_id(user_id):
        return personal_project_by_user.get(user_id)

    def admin_check_user_in_projects(_project_ids, _user_id):
        return []

    def admin_remove_users_from_project(project_id, user_ids):
        removed_from_project.append((project_id, list(user_ids)))

    rpc_funcs = {
        "project_get_by_id": project_get_by_id,
        "project_list": project_list,
        "projects_get_personal_project_id": projects_get_personal_project_id,
        "admin_check_user_in_projects": admin_check_user_in_projects,
        "admin_remove_users_from_project": admin_remove_users_from_project,
    }

    lifecycle_tasks.context.rpc_manager = FakeRpcManager(rpc_funcs)
    lifecycle_tasks.context.module_manager = types.SimpleNamespace(modules={})

    def list_users(user_ids=None):
        if user_ids:
            return [dict(u) for uid, u in users.items() if uid in user_ids]
        return [dict(u) for u in users.values()]

    def get_user(user_id=None, email=None, name=None):  # pylint: disable=unused-argument
        if user_id is not None:
            user = users.get(user_id)
        else:
            user = next((u for u in users.values() if u.get("email") == email), None)
        if not user:
            raise RuntimeError("User not found")
        return dict(user)

    def update_user(id_, name=None, last_login=None, suspended=None):  # pylint: disable=unused-argument
        if suspended is not None:
            users[id_]["suspended"] = suspended

    def delete_user(user_id):
        users.pop(user_id, None)

    lifecycle_tasks.auth.list_users = list_users
    lifecycle_tasks.auth.get_user = get_user
    lifecycle_tasks.auth.update_user = update_user
    lifecycle_tasks.auth.delete_user = delete_user

    db_module = types.ModuleType("tools.db")
    db_module.with_project_schema_session = lambda _project_id: FakeSession(projects)
    sys.modules["tools"].db = db_module
    sys.modules["tools.db"] = db_module

    sys.modules["tools"].elitea_config = {"ai_project_id": 999}

    class _Col:
        def __init__(self, name):
            self.name = name

        def __eq__(self, other):
            return ("eq", self.name, other)

    project_model = types.SimpleNamespace(id=_Col("id"), suspended=_Col("suspended"))
    models_project_module = types.ModuleType("plugins.projects.models.project")
    models_project_module.Project = project_model
    sys.modules["plugins.projects.models"] = types.ModuleType("plugins.projects.models")
    sys.modules["plugins.projects.models.project"] = models_project_module

    def delete_project(project_id, module):  # pylint: disable=unused-argument
        deleted_project_ids.append(project_id)
        projects.pop(project_id, None)

    api_v2_project_module = types.ModuleType("plugins.projects.api.v2.project")
    api_v2_project_module.delete_project = delete_project
    sys.modules["plugins.projects.api"] = types.ModuleType("plugins.projects.api")
    sys.modules["plugins.projects.api.v2"] = types.ModuleType("plugins.projects.api.v2")
    sys.modules["plugins.projects.api.v2.project"] = api_v2_project_module

    this_module = types.ModuleType("tools.this")
    this_module.for_module = lambda _name: types.SimpleNamespace(module=None)
    sys.modules["tools"].this = this_module
    sys.modules["tools.this"] = this_module

    return types.SimpleNamespace(
        projects=projects,
        users=users,
        personal_project_by_user=personal_project_by_user,
        deleted_project_ids=deleted_project_ids,
        removed_from_project=removed_from_project,
    )


def _param(**kwargs):
    return json.dumps(kwargs)


class TestParseParam:
    def test_empty_param_returns_empty_dict(self, lifecycle_tasks):
        assert lifecycle_tasks.parse_param("") == {}
        assert lifecycle_tasks.parse_param(None) == {}

    def test_json_object_param(self, lifecycle_tasks):
        result = lifecycle_tasks.parse_param(
            '{"scope": "team_projects", "project_ids": [1, 2], "dry_run": false}'
        )
        assert result == {"scope": "team_projects", "project_ids": [1, 2], "dry_run": False}

    def test_key_value_param(self, lifecycle_tasks):
        result = lifecycle_tasks.parse_param("scope=team_projects, dry_run=false")
        assert result == {"scope": "team_projects", "dry_run": "false"}

    def test_invalid_json_raises(self, lifecycle_tasks):
        with pytest.raises(ValueError):
            lifecycle_tasks.parse_param("{not valid json}")


class TestToList:
    def test_none_returns_empty(self, lifecycle_tasks):
        assert lifecycle_tasks._to_list(None) == []

    def test_list_passthrough(self, lifecycle_tasks):
        assert lifecycle_tasks._to_list([1, 2]) == [1, 2]

    def test_comma_separated_string(self, lifecycle_tasks):
        assert lifecycle_tasks._to_list("a@x.com, b@x.com") == ["a@x.com", "b@x.com"]

    def test_scalar_wrapped_in_list(self, lifecycle_tasks):
        assert lifecycle_tasks._to_list(5) == [5]


class TestToBool:
    def test_default_when_none(self, lifecycle_tasks):
        assert lifecycle_tasks._to_bool(None, "dry_run", default=True) is True
        assert lifecycle_tasks._to_bool(None, "dry_run", default=False) is False

    def test_bool_passthrough(self, lifecycle_tasks):
        assert lifecycle_tasks._to_bool(True, "dry_run") is True
        assert lifecycle_tasks._to_bool(False, "dry_run") is False

    def test_string_truthy_values(self, lifecycle_tasks):
        for value in ("true", "True", "1", "yes", "on"):
            assert lifecycle_tasks._to_bool(value, "dry_run") is True

    def test_string_falsy_values(self, lifecycle_tasks):
        for value in ("false", "0", "no", "off"):
            assert lifecycle_tasks._to_bool(value, "dry_run") is False

    def test_invalid_value_raises(self, lifecycle_tasks):
        with pytest.raises(ValueError):
            lifecycle_tasks._to_bool("flase", "dry_run")
        with pytest.raises(ValueError):
            lifecycle_tasks._to_bool("ture", "dry_run")


class TestToInt:
    def test_valid_int(self, lifecycle_tasks):
        assert lifecycle_tasks._to_int("5", "user_ids") == 5
        assert lifecycle_tasks._to_int(5, "user_ids") == 5

    def test_invalid_int_raises(self, lifecycle_tasks):
        with pytest.raises(ValueError):
            lifecycle_tasks._to_int("not-an-int", "user_ids")

    def test_int_list(self, lifecycle_tasks):
        assert lifecycle_tasks._to_int_list("1,2,3", "user_ids") == [1, 2, 3]


class TestIsPersonalProject:
    def test_personal_project_by_name(self, lifecycle_tasks):
        assert lifecycle_tasks.is_personal_project({"name": "project_user_42"}) is True

    def test_team_project_by_name(self, lifecycle_tasks):
        assert lifecycle_tasks.is_personal_project({"name": "acme-team"}) is False

    def test_missing_project(self, lifecycle_tasks):
        assert lifecycle_tasks.is_personal_project(None) is False


class TestIsProtectedUser:
    def test_protects_superadmin_id(self, lifecycle_tasks):
        assert lifecycle_tasks.is_protected_user({"id": 1, "email": "root@example.com"}) is True

    def test_protects_system_user_email(self, lifecycle_tasks):
        assert lifecycle_tasks.is_protected_user(
            {"id": 55, "email": "system_user_55@centry.user"}
        ) is True

    def test_does_not_protect_lookalike_email(self, lifecycle_tasks):
        assert lifecycle_tasks.is_protected_user(
            {"id": 55, "email": "notsystem_user_55@centry.user"}
        ) is False

    def test_protects_executing_admin(self, lifecycle_tasks):
        assert lifecycle_tasks.is_protected_user({"id": 7, "email": "a@x.com"}, executing_user_id=7) is True

    def test_allows_regular_user(self, lifecycle_tasks):
        assert lifecycle_tasks.is_protected_user({"id": 7, "email": "a@x.com"}, executing_user_id=9) is False

    def test_missing_user_is_protected(self, lifecycle_tasks):
        assert lifecycle_tasks.is_protected_user(None) is True


class TestIsProtectedProject:
    def test_protects_matching_id(self, lifecycle_tasks):
        assert lifecycle_tasks.is_protected_project({"id": 1}, {1, 42}) is True

    def test_allows_non_matching_id(self, lifecycle_tasks):
        assert lifecycle_tasks.is_protected_project({"id": 2}, {1, 42}) is False

    def test_missing_project(self, lifecycle_tasks):
        assert lifecycle_tasks.is_protected_project(None, {1}) is False


class TestResolveExecutingUserId:
    def test_valid_int_string(self, lifecycle_tasks):
        assert lifecycle_tasks._resolve_executing_user_id("7") == 7

    def test_none_passthrough(self, lifecycle_tasks):
        assert lifecycle_tasks._resolve_executing_user_id(None) is None

    def test_non_numeric_auth_id_returns_none(self, lifecycle_tasks):
        assert lifecycle_tasks._resolve_executing_user_id("-") is None


class TestSuspendTeamProjects:
    def test_all_true_skips_protected_public_project(self, lifecycle_tasks, task_env):
        """B5: a public/AI project (ai_project_id) must never be suspended, even with all=True."""
        task_env.projects[999] = {"id": 999, "name": "public-project", "owner_id": 1, "suspended": False}
        task_env.projects[2] = {"id": 2, "name": "acme-team", "owner_id": 3, "suspended": False}
        #
        lifecycle_tasks.suspend_projects_and_users(
            param=_param(scope="team_projects", all=True, dry_run=False),
            _executing_user_id="42",
        )
        #
        assert task_env.projects[999]["suspended"] is False
        assert task_env.projects[2]["suspended"] is True

    def test_live_run_without_resolvable_executing_admin_raises(self, lifecycle_tasks, task_env):
        """B2: '-' (token/non-user auth) must not crash; live runs must fail closed instead."""
        task_env.projects[2] = {"id": 2, "name": "acme-team", "owner_id": 3, "suspended": False}
        #
        with pytest.raises(ValueError):
            lifecycle_tasks.suspend_projects_and_users(
                param=_param(scope="team_projects", project_ids=[2], dry_run=False),
                _executing_user_id="-",
            )
        assert task_env.projects[2]["suspended"] is False

    def test_dry_run_with_non_numeric_executing_admin_does_not_raise(self, lifecycle_tasks, task_env):
        task_env.projects[2] = {"id": 2, "name": "acme-team", "owner_id": 3, "suspended": False}
        #
        lifecycle_tasks.suspend_projects_and_users(
            param=_param(scope="team_projects", project_ids=[2], dry_run=True),
            _executing_user_id="-",
        )
        assert task_env.projects[2]["suspended"] is False


class TestSuspendPrivateWithUsers:
    def test_project_ids_alone_resolve_to_owner_and_suspend(self, lifecycle_tasks, task_env):
        """B1: project_ids must not be silently ignored under scope=private_with_users."""
        task_env.users[10] = {"id": 10, "email": "owner@x.com", "suspended": False}
        task_env.projects[101] = {"id": 101, "name": "project_user_10", "owner_id": 10, "suspended": False}
        task_env.personal_project_by_user[10] = 101
        #
        lifecycle_tasks.suspend_projects_and_users(
            param=_param(scope="private_with_users", project_ids=[101], dry_run=False),
            _executing_user_id="99",
        )
        #
        assert task_env.users[10]["suspended"] is True
        assert task_env.projects[101]["suspended"] is True

    def test_public_personal_project_is_protected(self, lifecycle_tasks, task_env):
        """B5: the personal-project side must also respect protected project ids."""
        task_env.users[10] = {"id": 10, "email": "owner@x.com", "suspended": False}
        task_env.projects[999] = {"id": 999, "name": "project_user_10", "owner_id": 10, "suspended": False}
        task_env.personal_project_by_user[10] = 999
        #
        lifecycle_tasks.suspend_projects_and_users(
            param=_param(scope="private_with_users", user_ids=[10], dry_run=False),
            _executing_user_id="99",
        )
        #
        assert task_env.users[10]["suspended"] is False
        assert task_env.projects[999]["suspended"] is False


class TestDeleteUsersCascade:
    def test_user_owning_team_project_is_skipped(self, lifecycle_tasks, task_env):
        """M1: deleting a user who owns a team project would orphan ownership - must be skipped."""
        task_env.users[10] = {"id": 10, "email": "owner@x.com", "suspended": False}
        task_env.projects[101] = {"id": 101, "name": "project_user_10", "owner_id": 10, "suspended": False}
        task_env.projects[2] = {"id": 2, "name": "acme-team", "owner_id": 10, "suspended": False}
        task_env.personal_project_by_user[10] = 101
        #
        lifecycle_tasks.delete_users_with_private_projects_cascade(
            param=_param(user_ids=[10], dry_run=False, confirm=True),
            _executing_user_id="99",
        )
        #
        assert 10 in task_env.users
        assert 101 in task_env.projects
        assert task_env.deleted_project_ids == []

    def test_regular_user_is_deleted_with_personal_project(self, lifecycle_tasks, task_env):
        task_env.users[10] = {"id": 10, "email": "owner@x.com", "suspended": False}
        task_env.projects[101] = {"id": 101, "name": "project_user_10", "owner_id": 10, "suspended": False}
        task_env.personal_project_by_user[10] = 101
        #
        lifecycle_tasks.delete_users_with_private_projects_cascade(
            param=_param(user_ids=[10], dry_run=False, confirm=True),
            _executing_user_id="99",
        )
        #
        assert 10 not in task_env.users
        assert task_env.deleted_project_ids == [101]

    def test_public_personal_project_blocks_deletion(self, lifecycle_tasks, task_env):
        """B5: a personal project that happens to be the protected public project id is never deleted."""
        task_env.users[10] = {"id": 10, "email": "owner@x.com", "suspended": False}
        task_env.projects[999] = {"id": 999, "name": "project_user_10", "owner_id": 10, "suspended": False}
        task_env.personal_project_by_user[10] = 999
        #
        lifecycle_tasks.delete_users_with_private_projects_cascade(
            param=_param(user_ids=[10], dry_run=False, confirm=True),
            _executing_user_id="99",
        )
        #
        assert 10 in task_env.users
        assert 999 in task_env.projects
        assert task_env.deleted_project_ids == []

    def test_personal_project_id_resolves_to_owner_and_deletes(self, lifecycle_tasks, task_env):
        """project_ids selector: a personal project id identifies its owner for cascade delete."""
        task_env.users[10] = {"id": 10, "email": "owner@x.com", "suspended": False}
        task_env.projects[101] = {"id": 101, "name": "project_user_10", "owner_id": 10, "suspended": False}
        task_env.personal_project_by_user[10] = 101
        #
        lifecycle_tasks.delete_users_with_private_projects_cascade(
            param=_param(project_ids=[101], dry_run=False, confirm=True),
            _executing_user_id="99",
        )
        #
        assert 10 not in task_env.users
        assert task_env.deleted_project_ids == [101]

    def test_team_project_id_is_skipped(self, lifecycle_tasks, task_env):
        """A team project id identifies no single user - must be skipped, not resolved to owner."""
        task_env.users[10] = {"id": 10, "email": "owner@x.com", "suspended": False}
        task_env.projects[2] = {"id": 2, "name": "acme-team", "owner_id": 10, "suspended": False}
        #
        lifecycle_tasks.delete_users_with_private_projects_cascade(
            param=_param(project_ids=[2], dry_run=False, confirm=True),
            _executing_user_id="99",
        )
        #
        assert 10 in task_env.users
        assert task_env.deleted_project_ids == []

    def test_user_named_twice_via_id_and_project_is_deleted_once(self, lifecycle_tasks, task_env):
        task_env.users[10] = {"id": 10, "email": "owner@x.com", "suspended": False}
        task_env.projects[101] = {"id": 101, "name": "project_user_10", "owner_id": 10, "suspended": False}
        task_env.personal_project_by_user[10] = 101
        #
        lifecycle_tasks.delete_users_with_private_projects_cascade(
            param=_param(user_ids=[10], project_ids=[101], dry_run=False, confirm=True),
            _executing_user_id="99",
        )
        #
        assert task_env.deleted_project_ids == [101]

    def test_no_selector_raises(self, lifecycle_tasks, task_env):
        with pytest.raises(ValueError):
            lifecycle_tasks.delete_users_with_private_projects_cascade(
                param=_param(dry_run=True),
                _executing_user_id="99",
            )

    def test_live_run_without_resolvable_executing_admin_raises(self, lifecycle_tasks, task_env):
        """B2: '-' auth id must not crash the run; live delete must fail closed instead."""
        task_env.users[10] = {"id": 10, "email": "owner@x.com", "suspended": False}
        task_env.projects[101] = {"id": 101, "name": "project_user_10", "owner_id": 10, "suspended": False}
        task_env.personal_project_by_user[10] = 101
        #
        with pytest.raises(ValueError):
            lifecycle_tasks.delete_users_with_private_projects_cascade(
                param=_param(user_ids=[10], dry_run=False, confirm=True),
                _executing_user_id="-",
            )
        assert 10 in task_env.users
