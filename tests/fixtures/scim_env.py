"""Loads the SCIM models and utils (#5202) without a running pylon: SQLite in place of Postgres."""
import importlib.util
import pathlib
import sys
import types
from contextlib import closing

import sqlalchemy as sa
from sqlalchemy.orm import declarative_base, sessionmaker

PLUGIN_ROOT = pathlib.Path(__file__).resolve().parents[2]
PACKAGE = "_admin_scim_5202"
SCHEMA = "centry"
MODULES = ("models.scim", "utils.scim.protocol", "utils.scim.tokens", "utils.scim.service",
           "utils.scim.projects", "utils.scim.graph", "utils.scim.guards")


def _stub_pylon():
    """ A log with every method the code uses (the runner's stub lacks ``exception``) """
    sys.modules.setdefault("pylon", types.ModuleType("pylon"))
    sys.modules.setdefault("pylon.core", types.ModuleType("pylon.core"))
    tools = sys.modules.setdefault("pylon.core.tools", types.ModuleType("pylon.core.tools"))
    log = getattr(tools, "log", None) or types.SimpleNamespace()
    for name in ("info", "debug", "warning", "error", "exception", "critical"):
        if not hasattr(log, name):
            setattr(log, name, lambda *a, **k: None)
    tools.log = log


def load():
    """The SCIM modules bound to a fresh declarative base: {name: module}, plus 'Base'"""
    _stub_pylon()
    tools = sys.modules.setdefault("tools", types.ModuleType("tools"))
    base = declarative_base()
    tools.db = types.SimpleNamespace(Base=base)
    tools.config = types.SimpleNamespace(POSTGRES_SCHEMA=SCHEMA, POSTGRES_TENANT_SCHEMA="tenant")
    sys.modules["tools.db"] = tools.db
    sys.modules["tools.config"] = tools.config
    #
    for name, path in ((PACKAGE, PLUGIN_ROOT), (f"{PACKAGE}.models", PLUGIN_ROOT / "models"),
                       (f"{PACKAGE}.utils", PLUGIN_ROOT / "utils"),
                       (f"{PACKAGE}.utils.scim", PLUGIN_ROOT / "utils" / "scim")):
        package = types.ModuleType(name)
        package.__path__ = [str(path)]
        sys.modules[name] = package
    #
    loaded = {"Base": base}
    for name in MODULES:
        path = PLUGIN_ROOT.joinpath(*name.split(".")).with_suffix(".py")
        spec = importlib.util.spec_from_file_location(f"{PACKAGE}.{name}", path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        loaded[name] = module
    return loaded


def session_factory(base, directory):
    """A get_session() over a SQLite file with every SCIM table created"""
    engine = sa.create_engine(f"sqlite:///{directory}/scim.db").execution_options(
        schema_translate_map={SCHEMA: None})
    base.metadata.create_all(engine)
    maker = sessionmaker(bind=engine)
    return lambda: closing(maker())


class FakePlatform:
    """The platform calls the SCIM code makes: users, projects, membership, suspension, audit"""

    def __init__(self, users=None, projects=None):
        self.users = {u["email"]: dict(u, suspended=u.get("suspended", False)) for u in (users or [])}
        self.next_user_id = 1000
        self.projects = {p["id"]: dict(p, suspended=False) for p in (projects or [])}  # id -> {name, suspended}
        self.next_project_id = 100
        self.members = {}  # project_id -> {user_id: [roles]}
        self.audit = []
        self.created_users = []
        self.fail_create_project = False

    # users
    def find_user(self, email):
        return self.users.get(email)

    def _user_by_id(self, user_id):
        return next((u for u in self.users.values() if u["id"] == user_id), None)

    def ensure_user(self, email):
        user = self.users.get(email)
        if user is None:
            user = {"id": self.next_user_id, "email": email, "suspended": False}
            self.next_user_id += 1
            self.users[email] = user
            self.created_users.append(email)
        return user["id"]

    def set_user_suspended(self, user_id, suspended):
        self._user_by_id(user_id)["suspended"] = suspended

    def is_user_suspended(self, user_id):
        return self._user_by_id(user_id)["suspended"]

    # projects
    def create_project(self, name):
        if self.fail_create_project:
            raise RuntimeError("project creation failed")
        project_id = self.next_project_id
        self.next_project_id += 1
        self.projects[project_id] = {"id": project_id, "name": name, "suspended": False}
        return project_id

    def rename_project(self, project_id, name):
        self.projects[project_id]["name"] = name

    def set_project_suspended(self, project_id, suspended):
        self.projects[project_id]["suspended"] = suspended

    # membership
    def project_user_ids(self, project_id):
        return list(self.members.get(project_id, {}))

    def add_member(self, project_id, user_id, role):
        members = self.members.setdefault(project_id, {})
        if user_id in members:
            return False
        members[user_id] = [role]
        return True

    def remove_member(self, project_id, user_id):
        self.members.get(project_id, {}).pop(user_id, None)

    def record_audit(self, event):
        self.audit.append(event)
