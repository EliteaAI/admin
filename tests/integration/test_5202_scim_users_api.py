"""#5202: POST /admin/users/<mode>/<project_id> on a SCIM-managed project. Only an ELITEA admin
(administration mode) adding a project admin (role admin only) gets through; DELETE is always refused."""
import importlib.util
import pathlib
import sys
import types

import pytest

PLUGIN_ROOT = pathlib.Path(__file__).resolve().parents[2]
PROTECTED, NORMAL = 7, 3


class FakeGuards:
    def is_protected(self, project_id):
        return project_id == PROTECTED

    def refusal(self, project_id, allowed=None):
        if not self.is_protected(project_id) or (allowed is not None and allowed(self)):
            return None
        return {"error": "managed by SCIM", "scim_managed": True}, 403

    def can_add_admin(self, project_id, roles):
        return list(roles) == ["admin"]

    def can_set_roles(self, project_id, user_ids, roles, member_ids):
        return bool(roles) and set(user_ids) <= set(member_ids)


class Request:
    def __init__(self):
        self.json = {}
        self.args = {}


@pytest.fixture
def api(monkeypatch):
    request = Request()
    calls = []
    auth = types.ModuleType("tools.auth")
    auth.decorators = types.SimpleNamespace(check_api=lambda config: (lambda f: f))
    auth.list_project_users = lambda project_id: [5]
    tools = types.ModuleType("tools")
    tools.auth = auth
    tools.api_tools = types.SimpleNamespace(APIModeHandler=object, APIBase=object, endpoint_metrics=lambda f: f)
    tools.register_openapi = lambda **k: (lambda f: f)
    pylon_tools = types.ModuleType("pylon.core.tools")
    pylon_tools.log = types.SimpleNamespace(info=lambda *a, **k: None)
    utils = types.ModuleType("fake5202users.utils")
    utils.validate_role_assignment = lambda roles: (True, [])
    utils.get_role_validation_error = lambda roles: ({}, 400)
    pd_module = types.ModuleType("fake5202users.models.pd.user_input_field")
    pd_module.UserInputFieldPD = lambda **k: None
    stubs = {
        "tools": tools, "tools.auth": auth, "flask": types.SimpleNamespace(request=request),
        "pylon": types.ModuleType("pylon"), "pylon.core": types.ModuleType("pylon.core"),
        "pylon.core.tools": pylon_tools, "pydantic": types.SimpleNamespace(ValidationError=ValueError),
        "pydantic.v1": types.SimpleNamespace(ValidationError=ValueError),
        "fake5202users.utils": utils, "fake5202users.models.pd.user_input_field": pd_module,
    }
    for name in ("fake5202users", "fake5202users.api", "fake5202users.api.v2", "fake5202users.models",
                 "fake5202users.models.pd"):
        package = types.ModuleType(name)
        package.__path__ = []
        stubs[name] = package
    for name, module in stubs.items():
        monkeypatch.setitem(sys.modules, name, module)
    spec = importlib.util.spec_from_file_location("fake5202users.api.v2.users", PLUGIN_ROOT / "api" / "v2" / "users.py")
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)

    def add_user_to_project_or_create(email, project_id, roles, admin_grant=False):
        calls.append((email, project_id, roles, admin_grant))
        return {"status": "ok", "id": 9, "email": email}

    def update_roles_for_user(project_id, user_ids, roles):
        calls.append(("roles", project_id, list(user_ids), roles))
        return True

    instance = module.API()
    instance.module = types.SimpleNamespace(
        scim=types.SimpleNamespace(guards=FakeGuards()),
        context=types.SimpleNamespace(
            rpc_manager=types.SimpleNamespace(call=types.SimpleNamespace(
                add_user_to_project_or_create=add_user_to_project_or_create,
                update_roles_for_user=update_roles_for_user)),
            event_manager=types.SimpleNamespace(fire_event=lambda *a: None)),
        remove_users_from_project=lambda *a: calls.append(("remove",) + a),
    )
    return instance, request, calls


def post(api, project_id, roles, mode):
    instance, request, _ = api
    request.json = {"emails": ["new@contoso.com"], "roles": roles}
    return instance.post(project_id=project_id, mode=mode)


def test_elitea_admin_adds_project_admin_to_scim_project(api):
    result = post(api, PROTECTED, ["admin"], "administration")
    assert result[1] == 200
    assert api[2] == [("new@contoso.com", PROTECTED, ["admin"], True)]


@pytest.mark.parametrize("roles, mode", [
    (["admin"], "default"),            # a project admin, not an ELITEA admin
    (["viewer"], "administration"),
    (["admin", "editor"], "administration"),
])
def test_other_adds_to_scim_project_are_refused(api, roles, mode):
    result = post(api, PROTECTED, roles, mode)
    assert result[1] == 403 and result[0]["scim_managed"] is True
    assert api[2] == []


def test_normal_project_add_is_not_an_admin_grant(api):
    result = post(api, NORMAL, ["viewer"], "default")
    assert result[1] == 200
    assert api[2] == [("new@contoso.com", NORMAL, ["viewer"], False)]


def test_remove_from_scim_project_is_refused_even_in_administration(api):
    instance, request, calls = api
    request.args = {"id[]": "5"}
    result = instance.delete(project_id=PROTECTED, mode="administration")
    assert result[1] == 403 and calls == []



def put(api, project_id, user_id, roles):
    instance, request, _ = api
    request.json = {"id": user_id, "roles": roles}
    return instance.put(project_id=project_id, mode="administration")


def test_role_change_of_member_in_scim_project_is_allowed(api):
    result = put(api, PROTECTED, 5, ["editor"])
    assert result[1] == 200 and api[2] == [("roles", PROTECTED, [5], ["editor"])]


@pytest.mark.parametrize("user_id, roles", [(5, []), (9, ["viewer"])])
def test_role_change_that_removes_or_adds_is_refused_before_the_rpc(api, user_id, roles):
    """ The RPC's own refusal arrives as a RuntimeError over RPC: the API checks first and answers 403 """
    result = put(api, PROTECTED, user_id, roles)
    assert result[1] == 403 and result[0]["scim_managed"] is True
    assert api[2] == []
