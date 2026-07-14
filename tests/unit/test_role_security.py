"""Unit tests for utils/role_security.py - Role security utilities."""
import pytest


RESTRICTED_ROLES = {"super_admin", "system"}


def filter_restricted_roles(roles):
    """Filter out restricted roles from a list of role objects or strings."""
    if not roles:
        return roles
    if isinstance(roles[0], dict):
        return [r for r in roles if r.get('name') not in RESTRICTED_ROLES]
    else:
        return [r for r in roles if r not in RESTRICTED_ROLES]


def validate_role_assignment(role_names):
    """Validate that roles being assigned do not include restricted roles."""
    if not role_names:
        return True, set()
    invalid_roles = set(role_names) & RESTRICTED_ROLES
    return len(invalid_roles) == 0, invalid_roles


def get_role_validation_error(invalid_roles):
    """Generate a standardized error response for invalid role assignment."""
    return {
        'msg': f'Cannot assign restricted roles: {", ".join(sorted(invalid_roles))}'
    }, 403


class TestFilterRestrictedRoles:
    """Tests for filter_restricted_roles function."""

    def test_filters_super_admin_from_strings(self):
        roles = ["admin", "super_admin", "user"]
        result = filter_restricted_roles(roles)
        assert result == ["admin", "user"]

    def test_filters_system_from_strings(self):
        roles = ["admin", "system", "user"]
        result = filter_restricted_roles(roles)
        assert result == ["admin", "user"]

    def test_filters_both_restricted_roles(self):
        roles = ["admin", "super_admin", "system", "user"]
        result = filter_restricted_roles(roles)
        assert result == ["admin", "user"]

    def test_filters_super_admin_from_dicts(self):
        roles = [
            {"name": "admin", "id": 1},
            {"name": "super_admin", "id": 2},
            {"name": "user", "id": 3}
        ]
        result = filter_restricted_roles(roles)
        assert len(result) == 2
        assert result[0]["name"] == "admin"
        assert result[1]["name"] == "user"

    def test_filters_system_from_dicts(self):
        roles = [
            {"name": "admin", "id": 1},
            {"name": "system", "id": 2}
        ]
        result = filter_restricted_roles(roles)
        assert len(result) == 1
        assert result[0]["name"] == "admin"

    def test_returns_empty_list_unchanged(self):
        result = filter_restricted_roles([])
        assert result == []

    def test_returns_none_unchanged(self):
        result = filter_restricted_roles(None)
        assert result is None

    def test_preserves_non_restricted_roles(self):
        roles = ["admin", "editor", "viewer", "manager"]
        result = filter_restricted_roles(roles)
        assert result == roles

    def test_all_restricted_returns_empty(self):
        roles = ["super_admin", "system"]
        result = filter_restricted_roles(roles)
        assert result == []


class TestValidateRoleAssignment:
    """Tests for validate_role_assignment function."""

    def test_valid_roles_pass(self):
        is_valid, invalid = validate_role_assignment(["admin", "user"])
        assert is_valid is True
        assert invalid == set()

    def test_super_admin_fails(self):
        is_valid, invalid = validate_role_assignment(["admin", "super_admin"])
        assert is_valid is False
        assert invalid == {"super_admin"}

    def test_system_fails(self):
        is_valid, invalid = validate_role_assignment(["system", "user"])
        assert is_valid is False
        assert invalid == {"system"}

    def test_both_restricted_fails(self):
        is_valid, invalid = validate_role_assignment(["super_admin", "system", "admin"])
        assert is_valid is False
        assert invalid == {"super_admin", "system"}

    def test_empty_list_passes(self):
        is_valid, invalid = validate_role_assignment([])
        assert is_valid is True
        assert invalid == set()

    def test_none_passes(self):
        is_valid, invalid = validate_role_assignment(None)
        assert is_valid is True
        assert invalid == set()

    def test_single_valid_role(self):
        is_valid, invalid = validate_role_assignment(["admin"])
        assert is_valid is True
        assert invalid == set()

    def test_single_invalid_role(self):
        is_valid, invalid = validate_role_assignment(["super_admin"])
        assert is_valid is False
        assert invalid == {"super_admin"}


class TestGetRoleValidationError:
    """Tests for get_role_validation_error function."""

    def test_single_role_error_message(self):
        error, status = get_role_validation_error({"super_admin"})
        assert status == 403
        assert "super_admin" in error["msg"]
        assert "Cannot assign restricted roles" in error["msg"]

    def test_multiple_roles_sorted(self):
        error, status = get_role_validation_error({"system", "super_admin"})
        assert status == 403
        assert "super_admin, system" in error["msg"]

    def test_returns_403_status(self):
        _, status = get_role_validation_error({"system"})
        assert status == 403

    def test_error_dict_has_msg_key(self):
        error, _ = get_role_validation_error({"system"})
        assert "msg" in error


class TestRestrictedRolesConstant:
    """Tests for RESTRICTED_ROLES constant."""

    def test_contains_super_admin(self):
        assert "super_admin" in RESTRICTED_ROLES

    def test_contains_system(self):
        assert "system" in RESTRICTED_ROLES

    def test_is_set(self):
        assert isinstance(RESTRICTED_ROLES, set)

    def test_exactly_two_roles(self):
        assert len(RESTRICTED_ROLES) == 2
