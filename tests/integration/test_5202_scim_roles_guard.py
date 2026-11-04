"""#5202 (AC-12, AC-13): the membership RPCs refuse changes to SCIM-managed projects, except the SCIM sync's own
calls and role changes of existing members to a non-empty set."""
import importlib.util
import pathlib
import sys
import types

import pytest

PLUGIN_ROOT = pathlib.Path(__file__).resolve().parents[2]
PROTECTED = 7


class FakeAuth:
    def __init__(self):
        self.roles = {(PROTECTED, 5): {1}, (3, 5): {1}}   # (project, user) -> role ids
        self.role_ids = {"viewer": 1, "editor": 2, "admin": 3}

    def list_project_user_roles(self, project_id, user_id=None):
        return [{"user_id": u, "role_id": r} for (p, u), ids in self.roles.items()
                if p == project_id and (user_id is None or u == user_id) for r in ids]

    def get_project_role(self, project_id, name):
        return {"id": self.role_ids[name]} if name in self.role_ids else None

    def add_project_user_role(self, project_id, user_id, role_id):
        self.roles.setdefault((project_id, user_id), set()).add(role_id)

    def update_project_user_roles(self, project_id, user_id, role_ids):
        if role_ids:
            self.roles[(project_id, user_id)] = set(role_ids)
        else:
            self.roles.pop((project_id, user_id), None)

    def list_project_roles(self, project_id):
        return [{"id": i, "name": n} for n, i in self.role_ids.items()]

    def list_project_users(self, project_id):
        return [u for (p, u) in self.roles if p == project_id]


class FakeGuards:
    def is_protected(self, project_id):
        return project_id == PROTECTED

    def can_change_membership(self, project_id):
        return not self.is_protected(project_id)

    def can_add_admin(self, project_id, roles):
        return not self.is_protected(project_id) or list(roles) == ["admin"]

    def can_set_roles(self, project_id, user_ids, roles, member_ids):
        return not self.is_protected(project_id) or (bool(roles) and set(user_ids) <= set(member_ids))


@pytest.fixture
def rpc(monkeypatch):
    fake_auth = FakeAuth()
    tools = types.ModuleType("tools")
    for name in ("rpc_tools", "db", "db_tools"):
        setattr(tools, name, types.SimpleNamespace())
    tools.auth = fake_auth
    pylon_tools = types.ModuleType("pylon.core.tools")
    pylon_tools.web = types.SimpleNamespace(rpc=lambda *a, **k: (lambda f: f))
    pylon_tools.log = types.SimpleNamespace(info=lambda *a, **k: None)
    flask = types.ModuleType("flask")
    flask.g = types.SimpleNamespace()
    for name, module in (("tools", tools), ("pylon", types.ModuleType("pylon")),
                         ("pylon.core", types.ModuleType("pylon.core")), ("pylon.core.tools", pylon_tools),
                         ("flask", flask)):
        monkeypatch.setitem(sys.modules, name, module)
    for name, path in (("fakeadmin5202", PLUGIN_ROOT), ("fakeadmin5202.rpc", PLUGIN_ROOT / "rpc"),
                       ("fakeadmin5202.utils", PLUGIN_ROOT / "utils"),
                       ("fakeadmin5202.utils.scim", PLUGIN_ROOT / "utils" / "scim")):
        package = types.ModuleType(name)
        package.__path__ = [str(path)]
        monkeypatch.setitem(sys.modules, name, package)
    guards_stub = types.ModuleType("fakeadmin5202.utils.scim.guards")
    guards_stub.MANAGED_MESSAGE = "managed by SCIM"
    guards_stub.ScimManagedError = type("ScimManagedError", (PermissionError,), {"__init__": lambda self: None})
    monkeypatch.setitem(sys.modules, "fakeadmin5202.utils.scim.guards", guards_stub)
    spec = importlib.util.spec_from_file_location("fakeadmin5202.rpc.roles", PLUGIN_ROOT / "rpc" / "roles.py")
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    # pylon binds @web.rpc methods to the plugin module object, not to an RPC() instance: only the
    # decorated functions exist there, so helpers on the RPC class are not reachable through ``self``
    instance = types.SimpleNamespace()
    for name in ("add_user_to_project", "remove_users_from_project", "update_roles_for_user"):
        setattr(instance, name, types.MethodType(getattr(module.RPC, name), instance))
    instance.scim = types.SimpleNamespace(guards=FakeGuards())
    events = []
    instance.context = types.SimpleNamespace(
        event_manager=types.SimpleNamespace(fire_event=lambda *a: events.append(a)))
    return instance, fake_auth


def test_add_member_to_protected_project_is_refused(rpc):
    instance, fake_auth = rpc
    with pytest.raises(PermissionError):
        instance.add_user_to_project(PROTECTED, 9, ["viewer"])
    assert (PROTECTED, 9) not in fake_auth.roles


def test_remove_member_from_protected_project_is_refused(rpc):
    instance, fake_auth = rpc
    with pytest.raises(PermissionError):
        instance.remove_users_from_project(PROTECTED, [5])
    assert (PROTECTED, 5) in fake_auth.roles


def test_platform_admin_may_add_project_admin(rpc):
    instance, fake_auth = rpc
    instance.add_user_to_project(PROTECTED, 9, ["admin"], admin_grant=True)
    assert fake_auth.roles[(PROTECTED, 9)] == {3}


@pytest.mark.parametrize("roles", [["viewer"], ["editor"], ["admin", "editor"]])
def test_admin_grant_only_allows_the_admin_role(rpc, roles):
    instance, fake_auth = rpc
    with pytest.raises(PermissionError):
        instance.add_user_to_project(PROTECTED, 9, roles, admin_grant=True)
    assert (PROTECTED, 9) not in fake_auth.roles


def test_scim_sync_may_add_and_remove(rpc):
    instance, fake_auth = rpc
    instance.add_user_to_project(PROTECTED, 9, ["viewer"], scim_sync=True)
    assert fake_auth.roles[(PROTECTED, 9)] == {1}
    instance.remove_users_from_project(PROTECTED, [9], scim_sync=True)
    assert (PROTECTED, 9) not in fake_auth.roles


def test_role_change_of_existing_member_is_allowed(rpc):
    instance, fake_auth = rpc
    instance.update_roles_for_user(PROTECTED, [5], ["editor", "admin"])
    assert fake_auth.roles[(PROTECTED, 5)] == {2, 3}


@pytest.mark.parametrize("user_ids, roles", [([5], []), ([9], ["viewer"]), ([5, 9], ["editor"])])
def test_role_change_that_removes_or_adds_is_refused(rpc, user_ids, roles):
    instance, fake_auth = rpc
    with pytest.raises(PermissionError):
        instance.update_roles_for_user(PROTECTED, user_ids, roles)
    assert fake_auth.roles[(PROTECTED, 5)] == {1} and (PROTECTED, 9) not in fake_auth.roles


def test_normal_projects_are_unaffected(rpc):
    instance, fake_auth = rpc
    instance.add_user_to_project(3, 9, ["viewer"])
    instance.update_roles_for_user(3, [9], [])
    instance.remove_users_from_project(3, [5])
    assert (3, 9) not in fake_auth.roles and (3, 5) not in fake_auth.roles


def test_without_scim_runtime_nothing_is_guarded(rpc):
    instance, fake_auth = rpc
    instance.scim = None
    instance.add_user_to_project(PROTECTED, 9, ["viewer"])
    assert (PROTECTED, 9) in fake_auth.roles
