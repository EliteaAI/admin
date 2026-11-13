"""#7507 (AC-9, AC-7): in a private project only its owner may hold the admin role. The membership RPCs drop
``admin`` for anyone else there (system user included); team projects and other roles are unaffected."""
import importlib.util
import pathlib
import sys
import types

import pytest

PLUGIN_ROOT = pathlib.Path(__file__).resolve().parents[2]
PRIVATE, TEAM = 2, 10
OWNER, OTHER, SYSTEM = 6, 3, 7
VIEWER, EDITOR, ADMIN = 1, 2, 3


class FakeAuth:
    def __init__(self):
        self.roles = {}   # (project, user) -> role ids
        self.role_ids = {"viewer": VIEWER, "editor": EDITOR, "admin": ADMIN}

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


class FakeRpcCall:
    def __init__(self, owner_lookup_fails=False):
        self.owner_lookup_fails = owner_lookup_fails

    def projects_get_project_kind(self, project_id):
        return "personal" if project_id == PRIVATE else "team"

    def projects_get_private_project_owner(self, project_id, require_member=True):
        assert require_member is False, "the owner is not a member yet while a private project is created"
        if self.owner_lookup_fails:
            raise RuntimeError("projects unavailable")
        return OWNER if project_id == PRIVATE else None


def _load(monkeypatch, fake_auth):
    tools = types.ModuleType("tools")
    for name in ("rpc_tools", "db", "db_tools"):
        setattr(tools, name, types.SimpleNamespace())
    tools.auth = fake_auth
    pylon_tools = types.ModuleType("pylon.core.tools")
    pylon_tools.web = types.SimpleNamespace(rpc=lambda *a, **k: (lambda f: f))
    pylon_tools.log = types.SimpleNamespace(
        info=lambda *a, **k: None, warning=lambda *a, **k: None, exception=lambda *a, **k: None)
    flask = types.ModuleType("flask")
    flask.g = types.SimpleNamespace()
    for name, module in (("tools", tools), ("pylon", types.ModuleType("pylon")),
                         ("pylon.core", types.ModuleType("pylon.core")), ("pylon.core.tools", pylon_tools),
                         ("flask", flask)):
        monkeypatch.setitem(sys.modules, name, module)
    for name, path in (("fakeadmin7507", PLUGIN_ROOT), ("fakeadmin7507.rpc", PLUGIN_ROOT / "rpc"),
                       ("fakeadmin7507.utils", PLUGIN_ROOT / "utils")):
        package = types.ModuleType(name)
        package.__path__ = [str(path)]
        monkeypatch.setitem(sys.modules, name, package)
    spec = importlib.util.spec_from_file_location("fakeadmin7507.rpc.roles", PLUGIN_ROOT / "rpc" / "roles.py")
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def rpc(monkeypatch):
    def make(owner_lookup_fails=False):
        fake_auth = FakeAuth()
        module = _load(monkeypatch, fake_auth)
        instance = types.SimpleNamespace()
        for name in ("add_user_to_project", "update_roles_for_user"):
            setattr(instance, name, types.MethodType(getattr(module.RPC, name), instance))
        instance.context = types.SimpleNamespace(
            rpc_manager=types.SimpleNamespace(
                call=FakeRpcCall(owner_lookup_fails),
                timeout=lambda _t: FakeRpcCall(owner_lookup_fails),
            ),
            event_manager=types.SimpleNamespace(fire_event=lambda *a: None),
        )
        return instance, fake_auth
    return make


def test_owner_gets_admin_in_own_private_project(rpc):
    instance, fake_auth = rpc()
    instance.add_user_to_project(PRIVATE, OWNER, ["admin", "editor", "viewer"])
    assert fake_auth.roles[(PRIVATE, OWNER)] == {ADMIN, EDITOR, VIEWER}


@pytest.mark.parametrize("user_id", [OTHER, SYSTEM])
def test_add_drops_admin_for_non_owner_in_private_project(rpc, user_id):
    instance, fake_auth = rpc()
    instance.add_user_to_project(PRIVATE, user_id, ["admin", "editor"])
    assert fake_auth.roles[(PRIVATE, user_id)] == {EDITOR}


@pytest.mark.parametrize("user_id", [OTHER, SYSTEM])
def test_update_drops_admin_for_non_owner_in_private_project(rpc, user_id):
    instance, fake_auth = rpc()
    instance.update_roles_for_user(PRIVATE, [user_id], ["admin", "viewer"])
    assert fake_auth.roles[(PRIVATE, user_id)] == {VIEWER}


def test_update_keeps_admin_for_owner_and_drops_it_for_others_in_one_call(rpc):
    instance, fake_auth = rpc()
    instance.update_roles_for_user(PRIVATE, [OWNER, OTHER], ["admin", "editor"])
    assert fake_auth.roles[(PRIVATE, OWNER)] == {ADMIN, EDITOR}
    assert fake_auth.roles[(PRIVATE, OTHER)] == {EDITOR}


def test_admin_only_request_for_non_owner_grants_nothing(rpc):
    instance, fake_auth = rpc()
    instance.add_user_to_project(PRIVATE, OTHER, ["admin"])
    assert (PRIVATE, OTHER) not in fake_auth.roles


def test_admin_only_update_for_non_owner_keeps_current_roles(rpc):
    instance, fake_auth = rpc()
    instance.add_user_to_project(PRIVATE, OTHER, ["viewer"])
    instance.update_roles_for_user(PRIVATE, [OTHER], ["admin"])
    assert fake_auth.roles[(PRIVATE, OTHER)] == {VIEWER}


def test_unverifiable_owner_drops_admin_for_everyone(rpc):
    instance, fake_auth = rpc(owner_lookup_fails=True)
    instance.add_user_to_project(PRIVATE, OWNER, ["admin", "editor"])
    assert fake_auth.roles[(PRIVATE, OWNER)] == {EDITOR}


def test_team_projects_are_unaffected(rpc):
    instance, fake_auth = rpc()
    instance.add_user_to_project(TEAM, OTHER, ["admin"])
    instance.update_roles_for_user(TEAM, [SYSTEM], ["admin", "viewer"])
    assert fake_auth.roles[(TEAM, OTHER)] == {ADMIN}
    assert fake_auth.roles[(TEAM, SYSTEM)] == {ADMIN, VIEWER}


def test_non_admin_roles_in_private_project_are_unaffected(rpc):
    instance, fake_auth = rpc()
    instance.update_roles_for_user(PRIVATE, [OTHER], ["editor", "viewer"])
    assert fake_auth.roles[(PRIVATE, OTHER)] == {EDITOR, VIEWER}
