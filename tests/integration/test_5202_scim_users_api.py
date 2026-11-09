"""#5202 (AC-12, AC-18): /admin/users/<mode>/<project_id> on a project linked to a SCIM group. Adding and
role changes work as usual; removing synced members (or clearing their roles) is 403; rows say which are synced."""
import importlib.util
import pathlib
import sys
import types

import pytest

PLUGIN_ROOT = pathlib.Path(__file__).resolve().parents[2]
PROTECTED, NORMAL = 7, 3


class FakeGuards:
    def is_linked(self, project_id):
        return project_id == PROTECTED

    def synced_user_ids(self, project_id):
        return frozenset({5}) if project_id == PROTECTED else frozenset()

    def refusal(self, project_id, user_ids, roles=None):
        hit = sorted(set(user_ids) & self.synced_user_ids(project_id))
        return None if roles or not hit else ({"error": "synced", "scim_synced": hit}, 403)


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

    def add_user_to_project_or_create(email, project_id, roles):
        calls.append((email, project_id, roles))
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


@pytest.mark.parametrize("roles, mode", [(["viewer"], "default"), (["admin"], "administration")])
def test_manual_add_to_linked_project_is_allowed(api, roles, mode):
    result = post(api, PROTECTED, roles, mode)
    assert result[1] == 200 and api[2] == [("new@contoso.com", PROTECTED, roles)]


def delete(api, ids):
    instance, request, calls = api
    request.args = {"id[]": ids}
    return instance.delete(project_id=PROTECTED, mode="administration")


def test_removing_a_synced_member_is_refused(api):
    result = delete(api, "9,5")
    assert result[1] == 403 and result[0]["scim_synced"] == [5] and api[2] == []


def test_removing_a_manual_member_is_allowed(api):
    result = delete(api, "9")
    assert result[1] == 204 and api[2][0][0] == "remove"


def put(api, project_id, user_id, roles):
    instance, request, _ = api
    request.json = {"id": user_id, "roles": roles}
    return instance.put(project_id=project_id, mode="administration")


def test_role_change_of_synced_member_is_allowed(api):
    result = put(api, PROTECTED, 5, ["editor"])
    assert result[1] == 200 and api[2] == [("roles", PROTECTED, [5], ["editor"])]


def test_clearing_roles_of_synced_member_is_refused_before_the_rpc(api):
    """ The RPC's own refusal arrives as a RuntimeError over RPC: the API checks first and answers 403 """
    result = put(api, PROTECTED, 5, [])
    assert result[1] == 403 and result[0]["scim_synced"] == [5] and api[2] == []


def test_rows_say_which_members_are_synced(api, monkeypatch):
    instance, request, _ = api
    request.args = {}
    roles = {5: ["viewer"], 9: ["editor"]}
    instance.module.get_users_roles_in_project = lambda project_id, filter_system_user: roles
    users_module = sys.modules["fake5202users.api.v2.users"]
    monkeypatch.setattr(users_module.auth, "list_users", lambda user_ids: [
        {"id": i, "name": f"u{i}", "email": f"u{i}@contoso.com", "last_login": None} for i in sorted(user_ids)],
        raising=False)
    instance.module.context.rpc_manager.call.social_get_users = lambda ids: []
    body, status = instance.get(project_id=PROTECTED, mode="default")
    assert status == 200 and body["scim_managed"] is True
    assert {r["id"]: r["scim_synced"] for r in body["rows"]} == {5: True, 9: False}
