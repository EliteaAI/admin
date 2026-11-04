"""#5202: the SCIM admin endpoints answer with what the admin UI reads (Tenant URL, tokens, groups)."""
import importlib.util
import pathlib
import sys
import types

import pytest

PLUGIN_ROOT = pathlib.Path(__file__).resolve().parents[2]
BASE_URL = "https://tunnel.example.com/api/v2/admin/scim/administration"


@pytest.fixture
def load(monkeypatch):
    """ api/v2/<name>.py with tools stubbed; this.module.scim is a fake runtime """
    runtime = types.SimpleNamespace(
        base_url=lambda: BASE_URL,
        service=types.SimpleNamespace(list_tokens=lambda: [{"id": 1, "name": "t", "last4": "abcd"}]),
        sync=types.SimpleNamespace(overview=lambda: [], graph_status=lambda: {"error": None}),
        graph_app_id=lambda: None,
    )
    tools = types.ModuleType("tools")
    tools.auth = types.SimpleNamespace(decorators=types.SimpleNamespace(check_api=lambda config: (lambda f: f)))
    tools.api_tools = types.SimpleNamespace(APIModeHandler=object, APIBase=object)
    tools.this = types.SimpleNamespace(module=types.SimpleNamespace(scim=runtime))
    tools.register_openapi = lambda **k: (lambda f: f)
    monkeypatch.setitem(sys.modules, "tools", tools)
    monkeypatch.setitem(sys.modules, "flask", types.SimpleNamespace(request=None, g=None))
    for name in ("fake5202admin", "fake5202admin.api", "fake5202admin.api.v2", "fake5202admin.utils",
                 "fake5202admin.utils.scim"):
        package = types.ModuleType(name)
        package.__path__ = []
        monkeypatch.setitem(sys.modules, name, package)
    protocol = types.ModuleType("fake5202admin.utils.scim.protocol")
    protocol.ScimError = type("ScimError", (Exception,), {})
    monkeypatch.setitem(sys.modules, protocol.__name__, protocol)

    def _load(name):
        spec = importlib.util.spec_from_file_location(
            f"fake5202admin.api.v2.{name}", PLUGIN_ROOT / "api" / "v2" / f"{name}.py")
        module = importlib.util.module_from_spec(spec)
        monkeypatch.setitem(sys.modules, spec.name, module)
        spec.loader.exec_module(module)
        return module.AdminAPI()

    return _load


def test_tokens_list_returns_tenant_url(load):
    body, status = load("scim_tokens").get()
    assert status == 200
    assert body["base_url"] == BASE_URL and body["total"] == 1


def test_groups_list_returns_rows_and_graph_status(load):
    body, status = load("scim_groups").get()
    assert status == 200 and body["rows"] == [] and body["graph"] == {"error": None}


def test_settings_returns_graph_app(load):
    body, status = load("scim_settings").get()
    assert status == 200 and body["graph_oauth_app_id"] is None
