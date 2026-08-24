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
