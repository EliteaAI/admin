"""AdminAPI role endpoints reject unknown modes with 400 before touching auth (issue #6880)."""
import importlib.util
import sys
import types

import pytest


class FakeAuth(types.ModuleType):
    def __init__(self):
        super().__init__("tools.auth")
        self.calls = []
        self.decorators = types.SimpleNamespace(check_api=lambda *a, **k: (lambda f: f))

    def get_roles(self, mode):
        self.calls.append(("get_roles", mode))
        return [{"name": "admin"}]

    def add_role(self, name, mode):
        self.calls.append(("add_role", mode))

    def update_role_name(self, name, new_name, mode):
        self.calls.append(("update_role_name", mode))

    def delete_role(self, name, mode):
        self.calls.append(("delete_role", mode))


@pytest.fixture
def api(plugin_root, monkeypatch):
    fake_auth = FakeAuth()
    tools = types.ModuleType("tools")
    tools.auth = fake_auth
    tools.db = None
    tools.api_tools = types.SimpleNamespace(APIModeHandler=object, APIBase=object)
    tools.register_openapi = lambda **k: (lambda f: f)
    monkeypatch.setitem(sys.modules, "tools", tools)
    monkeypatch.setitem(sys.modules, "tools.auth", fake_auth)
    for name in ("flask", "flask_restful"):
        monkeypatch.setitem(sys.modules, name, types.SimpleNamespace(g=None, request=None))
    pylon_tools = types.ModuleType("pylon.core.tools")
    pylon_tools.log = None
    for name in ("pylon", "pylon.core"):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    monkeypatch.setitem(sys.modules, "pylon.core.tools", pylon_tools)
    sqlalchemy = types.ModuleType("sqlalchemy")
    sqlalchemy.schema = None
    monkeypatch.setitem(sys.modules, "sqlalchemy", sqlalchemy)

    utils = types.ModuleType("fakeadmin.utils")
    utils.filter_restricted_roles = lambda roles: roles
    for name in ("fakeadmin", "fakeadmin.api", "fakeadmin.api.v2"):
        package = types.ModuleType(name)
        package.__path__ = []
        monkeypatch.setitem(sys.modules, name, package)
    monkeypatch.setitem(sys.modules, "fakeadmin.utils", utils)

    spec = importlib.util.spec_from_file_location(
        "fakeadmin.api.v2.roles", plugin_root / "api" / "v2" / "roles.py"
    )
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "fakeadmin.api.v2.roles", module)
    spec.loader.exec_module(module)
    module.request = types.SimpleNamespace(json={"name": "a", "new_name": "b"})
    return module, fake_auth


def call_all(handler, mode):
    return [
        handler.get(mode), handler.post(mode), handler.put(mode), handler.delete(mode),
    ]


def test_unknown_mode_gets_400_and_never_reaches_auth(api):
    module, fake_auth = api

    results = call_all(module.AdminAPI(), "developer")

    assert all(r == ({"error": "Unknown role mode: developer"}, 400) for r in results)
    assert fake_auth.calls == []


@pytest.mark.parametrize("mode", ["administration", "default"])
def test_known_modes_reach_auth(api, mode):
    module, fake_auth = api

    call_all(module.AdminAPI(), mode)

    assert [c[0] for c in fake_auth.calls] == ["get_roles", "add_role", "update_role_name", "delete_role"]
    assert {c[1] for c in fake_auth.calls} == {mode}
