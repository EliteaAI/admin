"""The permission matrix PUTs persist only strings code registers or checks (issue #6874).

Bare group nodes like "admin" or "configurations" used to land in role_permission
because the Roles matrix group toggle sent them and every PUT stored whatever
name arrived. They match nothing in has_access, so they are pure noise.
"""
import importlib.util
import sys
import types

import pytest

KNOWN = {"configuration.roles", "runtime.plugins", "projects.projects"}


class FakeAuth(types.ModuleType):
    def __init__(self):
        super().__init__("tools.auth")
        self.local_permissions = set(KNOWN)
        self.granted = {("admin", "runtime.plugins")}
        self.added, self.removed, self.project_added = [], [], []
        self.decorators = types.SimpleNamespace(check_api=lambda *a, **k: (lambda f: f))

    def get_roles(self, mode):
        return [{"name": "admin"}, {"name": "viewer"}]

    def get_permissions(self, mode):
        return [{"name": r, "permission": p} for r, p in self.granted]

    def set_permission_for_role(self, role, perm, mode):
        self.added.append((role, perm))

    def remove_permission_from_role(self, role, perm, mode):
        self.removed.append((role, perm))

    def list_project_roles(self, project_id):
        return [{"id": 1, "name": "admin"}]

    def list_project_role_permissions(self, project_id):
        return []

    def add_project_role_permission(self, project_id, role_id, perm):
        self.project_added.append(perm)


@pytest.fixture
def api(plugin_root, monkeypatch):
    fake_auth = FakeAuth()
    tools = types.ModuleType("tools")
    tools.auth = fake_auth
    tools.api_tools = types.SimpleNamespace(APIModeHandler=object, APIBase=object)
    tools.register_openapi = lambda **k: (lambda f: f)
    tools.elitea_config = {"ai_project_id": 7}
    monkeypatch.setitem(sys.modules, "tools", tools)
    monkeypatch.setitem(sys.modules, "tools.auth", fake_auth)
    for name in ("flask", "flask_restful"):
        monkeypatch.setitem(sys.modules, name, types.SimpleNamespace(g=None, request=None))

    spec = importlib.util.spec_from_file_location(
        "admin_permissions_under_test", plugin_root / "api" / "v2" / "permissions.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    def put(handler_cls, payload, *args):
        module.request = types.SimpleNamespace(get_json=lambda: payload)
        return handler_cls().put(*args)

    return module, fake_auth, put


def test_known_rows_drops_unregistered_names(api):
    module, _, _ = api
    rows = [{"name": "admin"}, {"name": "runtime.plugins"}, {"name": "configurations"}, {}]

    assert module.known_rows(rows) == [{"name": "runtime.plugins"}]
    assert module.known_rows(None) == []


def test_admin_put_ignores_group_prefix_rows(api):
    module, fake_auth, put = api
    # The UI group toggle for "admin.*" sends the bare node alongside real children.
    payload = [
        {"name": "admin", "admin": True},
        {"name": "configurations", "viewer": True},
        {"name": "runtime.plugins", "admin": True},
        {"name": "configuration.roles", "viewer": True},
        {"name": "projects.projects"},  # the client always sends the full matrix
    ]

    put(module.AdminAPI, payload, "administration")

    assert fake_auth.added == [("viewer", "configuration.roles")]
    assert fake_auth.removed == []


def test_admin_put_drops_parent_prefix_of_a_registered_leaf(api):
    module, fake_auth, put = api
    # Realistic set: auth registers leaves only, so the parent prefix is not "known".
    fake_auth.local_permissions = {"configuration.evaluation.platform_dimensions.view"}
    payload = [
        {"name": "configuration.evaluation", "admin": True},
        {"name": "configuration.evaluation.platform_dimensions", "admin": True},
        {"name": "configuration.evaluation.platform_dimensions.view", "admin": True},
    ]

    put(module.AdminAPI, payload, "administration")

    assert fake_auth.added == [("admin", "configuration.evaluation.platform_dimensions.view")]


def test_public_put_ignores_group_prefix_rows(api):
    module, fake_auth, put = api
    payload = [{"name": "projects", "admin": True}, {"name": "projects.projects", "admin": True}]

    put(module.PublicProjectAPI, payload, "public")

    assert fake_auth.project_added == ["projects.projects"]
