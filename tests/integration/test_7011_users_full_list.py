"""Full list users endpoint returns all project members when limit is not set (EL-7011).

Tests for:
- TC-US04-10: No limit returns every project user with today's fields
- TC-US04-11: An offset without a limit is ignored
- TC-US04-12: The full list still returns when the avatar service is down
"""
import importlib.util
import sys
import types

import pytest

PROJECT_ID = 3
SYSTEM_USER_ID = 900
OUTSIDER_ID = 901


class FakeAuth(types.ModuleType):
    """Stub auth module for testing."""

    def __init__(self, users):
        super().__init__("tools.auth")
        self.users = users
        self.decorators = types.SimpleNamespace(check_api=lambda *a, **k: (lambda f: f))

    def list_users(self, user_ids=None):
        """Return user records."""
        return [dict(u) for u in self.users if user_ids is None or u["id"] in user_ids]


def make_user(user_id, name, email=None):
    """Helper to create user dict."""
    return {
        "id": user_id,
        "name": name,
        "email": email or f"u{user_id}@corp.test",
        "last_login": None,
    }


def default_users():
    """Create 45 members; 7 is coprime with 45, so names are unique and differ from id order."""
    return [make_user(i, f"User {(i * 7) % 45:02d}") for i in range(1, 46)]


class Env:
    """Test environment with loaded module and stubs."""

    def __init__(self, module, users, social_calls):
        self.module = module
        self.users = users
        self.social_calls = social_calls
        self.api = module.API()
        self.api.module = self._plugin(users, social_calls)

    @staticmethod
    def _plugin(users, social_calls):
        """Create stub plugin with get_users_roles_in_project and context.rpc_manager."""
        members = {u["id"]: ["viewer"] for u in users}

        def get_users_roles_in_project(project_id, filter_system_user=False):
            """Return member roles, optionally including system user."""
            roles = dict(members)
            if not filter_system_user:
                roles[SYSTEM_USER_ID] = ["system"]
            return roles

        def social_get_users(ids):
            """Record avatar request and return fake avatars."""
            social_calls.append(set(ids))
            return [{"user_id": i, "avatar": f"a{i}"} for i in ids]

        rpc = types.SimpleNamespace(call=types.SimpleNamespace(social_get_users=social_get_users))
        return types.SimpleNamespace(
            get_users_roles_in_project=get_users_roles_in_project,
            context=types.SimpleNamespace(rpc_manager=rpc),
        )

    def get(self, **args):
        """Call the endpoint with request args."""
        self.module.request = types.SimpleNamespace(args={k: str(v) for k, v in args.items()})
        return self.api.get(project_id=PROJECT_ID)


@pytest.fixture
def make_env(plugin_root, monkeypatch):
    """Factory fixture to create test environment."""

    def build(members=None):
        members = default_users() if members is None else members
        # Non-members: system user and outsider
        platform_users = members + [
            make_user(SYSTEM_USER_ID, "project_P_system"),
            make_user(OUTSIDER_ID, "Outsider Zed"),
        ]
        fake_auth = FakeAuth(platform_users)

        tools = types.ModuleType("tools")
        tools.auth = fake_auth
        tools.api_tools = types.SimpleNamespace(
            APIModeHandler=object, APIBase=object, endpoint_metrics=lambda f: f
        )
        tools.register_openapi = lambda **k: (lambda f: f)
        monkeypatch.setitem(sys.modules, "tools", tools)
        monkeypatch.setitem(sys.modules, "tools.auth", fake_auth)
        monkeypatch.setitem(sys.modules, "flask", types.SimpleNamespace(request=None))

        # Stub pydantic
        for name in ("pydantic", "pydantic.v1"):
            monkeypatch.setitem(sys.modules, name, types.SimpleNamespace(ValidationError=ValueError))

        pylon_tools = types.ModuleType("pylon.core.tools")
        pylon_tools.log = None
        for name in ("pylon", "pylon.core"):
            monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
        monkeypatch.setitem(sys.modules, "pylon.core.tools", pylon_tools)

        # Stub admin models and utils
        pd_module = types.ModuleType("fakeadmin.models.pd.user_input_field")
        pd_module.UserInputFieldPD = object
        utils = types.ModuleType("fakeadmin.utils")
        utils.validate_role_assignment = lambda roles: (True, [])
        utils.get_role_validation_error = lambda roles: ({}, 400)

        for name in ("fakeadmin", "fakeadmin.api", "fakeadmin.api.v2", "fakeadmin.models", "fakeadmin.models.pd"):
            package = types.ModuleType(name)
            package.__path__ = []
            monkeypatch.setitem(sys.modules, name, package)
        monkeypatch.setitem(sys.modules, "fakeadmin.models.pd.user_input_field", pd_module)
        monkeypatch.setitem(sys.modules, "fakeadmin.utils", utils)

        # Load the actual users.py module
        spec = importlib.util.spec_from_file_location(
            "fakeadmin.api.v2.users", plugin_root / "api" / "v2" / "users.py"
        )
        module = importlib.util.module_from_spec(spec)
        monkeypatch.setitem(sys.modules, "fakeadmin.api.v2.users", module)
        spec.loader.exec_module(module)

        env = Env(module, members, [])
        env.auth = fake_auth
        return env

    return build


@pytest.fixture
def env(make_env):
    """Test environment with default users."""
    return make_env()


def test_no_limit_returns_all_project_users(env):
    """TC-US04-10: No limit returns every project user with today's fields.

    When the request has no limit parameter, the endpoint returns all project members
    (45 users) with the same fields as before: id, name, email, roles, last_login, avatar.
    """
    result, status = env.get()

    assert status == 200
    assert result["total"] == 45, "Total should be 45 members"
    assert len(result["rows"]) == 45, "Should return all 45 members"

    # Verify that each row has the expected fields
    for row in result["rows"]:
        assert "id" in row
        assert "name" in row
        assert "email" in row
        assert "roles" in row
        assert "avatar" in row


def test_offset_without_limit_is_ignored(env):
    """TC-US04-11: An offset without a limit is ignored.

    When the request has an offset but no limit, the offset is ignored and
    all project members are returned.
    """
    result, status = env.get(offset=10)

    assert status == 200
    assert result["total"] == 45, "Total should be 45 members"
    assert len(result["rows"]) == 45, "Should return all 45 members, not starting at offset 10"


def test_full_list_without_avatar_service(env):
    """TC-US04-12: The full list still returns when the avatar service is down.

    When the avatar service (social_get_users) fails, the endpoint still returns
    all users but with no avatar data.
    """
    # Make social_get_users raise an error
    def failing_social_get_users(ids):
        raise KeyError("social service not available")

    env.api.module.context.rpc_manager.call.social_get_users = failing_social_get_users

    result, status = env.get()

    assert status == 200
    assert result["total"] == 45, "Total should be 45 members"
    assert len(result["rows"]) == 45, "Should return all 45 members"

    # Verify that avatars are None when service fails
    for row in result["rows"]:
        assert row.get("avatar") is None
