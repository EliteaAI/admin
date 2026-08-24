"""Unit tests for tasks/lifecycle_tasks.py - param parsing and protection helpers."""
import json

import pytest

PROTECTED_USER_ID = 1
PERSONAL_PROJECT_PREFIX = "project_user_"
SYSTEM_USER_EMAIL_SUFFIX = "@centry.user"


def _to_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return [value]


def _to_bool(value, default=False):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def parse_param(param):
    param = (param or "").strip()
    if not param:
        return {}
    if param.startswith("{"):
        return json.loads(param)
    parsed = {}
    for pair in param.split(","):
        pair = pair.strip()
        if not pair or "=" not in pair:
            continue
        key, _, value = pair.partition("=")
        parsed[key.strip()] = value.strip()
    return parsed


def is_personal_project(project):
    return bool(project) and str(project.get("name", "")).startswith(PERSONAL_PROJECT_PREFIX)


def is_protected_user(user, executing_user_id=None):
    if not user:
        return True
    if int(user["id"]) == PROTECTED_USER_ID:
        return True
    if str(user.get("email", "")).endswith(SYSTEM_USER_EMAIL_SUFFIX):
        return True
    if executing_user_id is not None and int(user["id"]) == int(executing_user_id):
        return True
    return False


class TestParseParam:
    def test_empty_param_returns_empty_dict(self):
        assert parse_param("") == {}
        assert parse_param(None) == {}

    def test_json_object_param(self):
        result = parse_param('{"scope": "team_projects", "project_ids": [1, 2], "dry_run": false}')
        assert result == {"scope": "team_projects", "project_ids": [1, 2], "dry_run": False}

    def test_key_value_param(self):
        result = parse_param("scope=team_projects, dry_run=false")
        assert result == {"scope": "team_projects", "dry_run": "false"}

    def test_invalid_json_raises(self):
        with pytest.raises(json.JSONDecodeError):
            parse_param("{not valid json}")


class TestToList:
    def test_none_returns_empty(self):
        assert _to_list(None) == []

    def test_list_passthrough(self):
        assert _to_list([1, 2]) == [1, 2]

    def test_comma_separated_string(self):
        assert _to_list("a@x.com, b@x.com") == ["a@x.com", "b@x.com"]

    def test_scalar_wrapped_in_list(self):
        assert _to_list(5) == [5]


class TestToBool:
    def test_default_when_none(self):
        assert _to_bool(None, default=True) is True
        assert _to_bool(None, default=False) is False

    def test_bool_passthrough(self):
        assert _to_bool(True) is True
        assert _to_bool(False) is False

    def test_string_truthy_values(self):
        for value in ("true", "True", "1", "yes", "on"):
            assert _to_bool(value) is True

    def test_string_falsy_values(self):
        for value in ("false", "0", "no", "off", ""):
            assert _to_bool(value) is False


class TestIsPersonalProject:
    def test_personal_project_by_name(self):
        assert is_personal_project({"name": "project_user_42"}) is True

    def test_team_project_by_name(self):
        assert is_personal_project({"name": "acme-team"}) is False

    def test_missing_project(self):
        assert is_personal_project(None) is False


class TestIsProtectedUser:
    def test_protects_superadmin_id(self):
        assert is_protected_user({"id": 1, "email": "root@example.com"}) is True

    def test_protects_system_user_email(self):
        assert is_protected_user({"id": 55, "email": "system_user_55@centry.user"}) is True

    def test_protects_executing_admin(self):
        assert is_protected_user({"id": 7, "email": "a@x.com"}, executing_user_id=7) is True

    def test_allows_regular_user(self):
        assert is_protected_user({"id": 7, "email": "a@x.com"}, executing_user_id=9) is False

    def test_missing_user_is_protected(self):
        assert is_protected_user(None) is True
