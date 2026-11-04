"""#5202: delete_ghost_users removes a never-logged-in user from team projects as a platform cleanup, so
members of SCIM-managed projects can still be deleted (the removal RPC refuses SCIM projects otherwise)."""
import importlib.util
import pathlib
import sys
import types

import pytest

PLUGIN_ROOT = pathlib.Path(__file__).resolve().parents[2]


class Rpc:
    def __init__(self):
        self.removed = []

    def project_list(self, filter_=None):
        return [{"id": 7, "name": "Sales"}]

    def projects_get_personal_project_id(self, user_id):
        return None

    def admin_check_user_in_projects(self, project_ids, user_id):
        return [7]

    def project_get_by_id(self, project_id):
        return {"id": project_id, "name": "Sales"} if project_id == 7 else None

    def admin_remove_users_from_project(self, project_id, user_ids, system_cleanup=False, **kwargs):
        if not system_cleanup:
            raise PermissionError("This project is managed by SCIM")
        self.removed.append((project_id, list(user_ids)))


@pytest.fixture
def tasks(monkeypatch):
    rpc = Rpc()
    deleted = []
    log = types.SimpleNamespace(**{n: (lambda *a, **k: None) for n in ("info", "warning", "error", "exception")})
    tools = types.ModuleType("tools")
    tools.context = types.SimpleNamespace(rpc_manager=types.SimpleNamespace(call=rpc, timeout=lambda _s: rpc))
    tools.log = log
    tools.auth = types.SimpleNamespace(
        list_users=lambda: [{"id": 10, "email": "member@x.com", "last_login": None}],
        delete_user=deleted.append,
    )
    tools.this = types.SimpleNamespace(for_module=lambda name: types.SimpleNamespace(module=None))
    poc = types.ModuleType("plugins.projects.rpc.poc")
    poc.is_system_user = lambda email: False
    project_api = types.ModuleType("plugins.projects.api.v2.project")
    project_api.delete_project = lambda **k: None
    stubs = {"tools": tools, "plugins.projects.rpc.poc": poc, "plugins.projects.api.v2.project": project_api}
    for name in ("plugins", "plugins.projects", "plugins.projects.rpc", "plugins.projects.api",
                 "plugins.projects.api.v2", "fake5202tasks", "fake5202tasks.tasks"):
        package = types.ModuleType(name)
        package.__path__ = []
        stubs[name] = package
    lifecycle = types.ModuleType("fake5202tasks.tasks.lifecycle_tasks")
    lifecycle.parse_param = lambda *a, **k: {}
    lifecycle._to_bool = bool  # pylint: disable=W0212
    logs = types.ModuleType("fake5202tasks.tasks.logs")
    logs.make_logger = lambda: None
    stubs[lifecycle.__name__] = lifecycle
    stubs[logs.__name__] = logs
    for name, module in stubs.items():
        monkeypatch.setitem(sys.modules, name, module)
    spec = importlib.util.spec_from_file_location("fake5202tasks.tasks.project_tasks",
                                                  PLUGIN_ROOT / "tasks" / "project_tasks.py")
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    return module, rpc, deleted


def test_ghost_user_in_scim_project_is_removed_and_deleted(tasks):
    module, rpc, deleted = tasks
    module.delete_ghost_users()
    assert rpc.removed == [(7, [10])]
    assert deleted == [10]
