"""Tests for utils/system_tokens.py and the prune_system_tokens task (issue #6489).

Weekly rotation used to add a non-expiring 'api' token per system user and
overwrite Vault, never deleting anything: dev accumulated ~33 live credentials
per project. The fix keeps exactly two - the new one and the one Vault held
before (in-flight predicts may still use it) - and the one-time task prunes the
existing backlog down to the Vault token plus the newest.

The auth pylon and Vault are replaced by an in-memory world so ordering and
"what survives" can be asserted exactly.
"""
import importlib
import importlib.util
import sys
import types

import pytest

TASKS_PACKAGE = "admin_prune_tasks_under_test"
ADMIN_USER = 1


class RecordingLog:
    def __init__(self):
        self.info_messages = []
        self.warnings = []
        self.exceptions = []

    @staticmethod
    def _format(message, args):
        return message % args if args else message

    def info(self, message, *args):
        self.info_messages.append(self._format(message, args))

    def warning(self, message, *args):
        self.warnings.append(self._format(message, args))

    def exception(self, message, *args):
        self.exceptions.append(self._format(message, args))

    def debug(self, message, *args):
        pass

    def error(self, message, *args):
        pass

    @property
    def text(self):
        return "\n".join(self.info_messages)


class StubMakeLogger:
    instances = []

    def __enter__(self):
        log = RecordingLog()
        StubMakeLogger.instances.append(log)
        return log

    def __exit__(self, *exc_info):
        return False


class FakeAuth:
    """In-memory auth_core token table; ids are one global sequence like the real one."""

    def __init__(self):
        self.tokens = {}
        self.next_id = 100
        self.events = []
        self.users = {"system@centry.user": ADMIN_USER}

    def seed(self, user_id, count, name="api", expires=None):
        ids = []
        for _ in range(count):
            ids.append(self._insert(user_id, name, expires))
        return ids

    def _insert(self, user_id, name, expires=None):
        self.next_id += 1
        self.tokens[self.next_id] = {
            "id": self.next_id, "user_id": user_id, "name": name,
            "expires": expires, "uuid": f"uuid-{self.next_id}",
        }
        return self.next_id

    def ids_of(self, user_id):
        return sorted(t["id"] for t in self.tokens.values() if t["user_id"] == user_id)

    def get_user(self, email):
        if email not in self.users:
            raise RuntimeError("no such user")
        return {"id": self.users[email]}

    def add_token(self, user_id, name=""):
        token_id = self._insert(user_id, name)
        self.events.append(("add", token_id))
        return token_id

    def encode_token(self, token_id):
        return f"jwt-{token_id}"

    def decode_token(self, token):
        if not token.startswith("jwt-"):
            raise ValueError("Invalid token")
        return dict(self.tokens[int(token[4:])])

    def list_tokens(self, user_id=None, name=None):
        return [
            dict(t) for t in self.tokens.values()
            if (user_id is None or t["user_id"] == user_id)
            and (name is None or t["name"] == name)
        ]

    def delete_token(self, token_id):
        self.events.append(("delete", token_id))
        return 1 if self.tokens.pop(token_id, None) else 0


class FakeVault:
    def __init__(self, world, auth_token=None):
        self.world = world
        self.secrets = {"other": "kept"}
        if auth_token is not None:
            self.secrets["auth_token"] = auth_token
        self.fail_set = False

    def get_secrets(self):
        return dict(self.secrets)

    def set_secrets(self, secrets):
        if self.fail_set:
            raise RuntimeError("vault down")
        self.world.auth.events.append(("vault", secrets.get("auth_token")))
        self.secrets = dict(secrets)


class World:
    """Admin space + projects; project N's system user id is 1000+N."""

    def __init__(self):
        self.auth = FakeAuth()
        self.vaults = {None: FakeVault(self)}
        self.project_ids = []
        self.sleeps = []

    def add_project(self, project_id, backlog, vault_token="newest"):
        user_id = 1000 + project_id
        self.auth.users[f"system_user_{project_id}@centry.user"] = user_id
        ids = self.auth.seed(user_id, backlog)
        token = {"newest": ids[-1] if ids else None, "oldest": ids[0] if ids else None}.get(
            vault_token, vault_token,
        )
        self.vaults[project_id] = FakeVault(self, f"jwt-{token}" if isinstance(token, int) else token)
        self.project_ids.append(project_id)
        return user_id, ids

    def vault_client(self, project=None):
        # Mirrors get_project_id: the real client resolves an int via a DB lookup, a dict directly
        assert project is None or isinstance(project, dict), "use project_vault(), not VaultClient(int)"
        return self.vaults[None if project is None else project["id"]]

    def get_project_user(self, project_id):
        email = f"system_user_{project_id}@centry.user"
        if email not in self.auth.users:
            return None
        return {"id": self.auth.users[email]}

    def project_list(self, filter_=None):
        assert filter_ == {"create_success": True}
        return [{"id": pid} for pid in self.project_ids]

    def timeout(self, _seconds):
        return self


@pytest.fixture
def world(plugin_root, monkeypatch):
    """Load the real utils/system_tokens.py wired to an in-memory World."""
    import tools  # stubbed by run_tests.py

    w = World()
    monkeypatch.setattr(tools, "context", types.SimpleNamespace(rpc_manager=w), raising=False)
    monkeypatch.setattr(tools, "VaultClient", w.vault_client, raising=False)
    monkeypatch.setattr(tools, "log", RecordingLog(), raising=False)

    spec = importlib.util.spec_from_file_location(
        "admin_system_tokens_under_test", plugin_root / "utils" / "system_tokens.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.auth = w.auth
    mod.context = types.SimpleNamespace(rpc_manager=w)
    mod.VaultClient = w.vault_client
    mod.log = RecordingLog()
    mod.time = types.SimpleNamespace(sleep=w.sleeps.append)

    # Both lazy imports: projects' get_project_user, and the task's system_tokens
    projects_utils = types.ModuleType("plugins.projects.utils")
    projects_utils.get_project_user = w.get_project_user
    admin_utils = types.ModuleType("plugins.admin.utils")
    admin_utils.system_tokens = mod
    for name, module in {
        "plugins": types.ModuleType("plugins"),
        "plugins.projects": types.ModuleType("plugins.projects"),
        "plugins.projects.utils": projects_utils,
        "plugins.admin": types.ModuleType("plugins.admin"),
        "plugins.admin.utils": admin_utils,
    }.items():
        monkeypatch.setitem(sys.modules, name, module)

    w.mod = mod
    return w


@pytest.fixture
def token_tasks(plugin_root, world, monkeypatch):
    tasks_package = types.ModuleType(TASKS_PACKAGE)
    tasks_package.__path__ = [str(plugin_root / "tasks")]
    logs_stub = types.ModuleType(f"{TASKS_PACKAGE}.logs")
    logs_stub.make_logger = StubMakeLogger
    monkeypatch.setitem(sys.modules, TASKS_PACKAGE, tasks_package)
    monkeypatch.setitem(sys.modules, f"{TASKS_PACKAGE}.logs", logs_stub)
    try:
        mod = importlib.import_module(f"{TASKS_PACKAGE}.token_tasks")
        mod.time = types.SimpleNamespace(sleep=world.sleeps.append, time=__import__("time").time)
        yield mod
    finally:
        for name in (f"{TASKS_PACKAGE}.token_tasks", f"{TASKS_PACKAGE}.lifecycle_tasks"):
            sys.modules.pop(name, None)


@pytest.fixture
def prune(token_tasks):
    def _run(param=None):
        StubMakeLogger.instances.clear()
        kwargs = {} if param is None else {"param": param}
        try:
            token_tasks.prune_system_tokens(**kwargs)
        finally:
            log = StubMakeLogger.instances[-1]
        return log
    return _run


# --- vault_token_id ----------------------------------------------------------


def test_vault_token_id_resolves_own_token(world):
    user_id, ids = world.add_project(5, 3)
    assert world.mod.vault_token_id({"auth_token": f"jwt-{ids[1]}"}, user_id) == ids[1]


@pytest.mark.parametrize("secrets", [{}, None, {"auth_token": ""}, {"auth_token": "garbage"}, {"auth_token": "jwt-999999"}])
def test_vault_token_id_is_none_for_missing_or_invalid(world, secrets):
    user_id, _ = world.add_project(5, 3)
    assert world.mod.vault_token_id(secrets, user_id) is None


def test_vault_token_id_ignores_a_token_of_another_user(world):
    """A copy-pasted foreign token must not be mistaken for this user's previous one."""
    user_a, _ = world.add_project(5, 2)
    _, ids_b = world.add_project(6, 2)
    assert world.mod.vault_token_id({"auth_token": f"jwt-{ids_b[0]}"}, user_a) is None


# --- rotation ----------------------------------------------------------------


def test_rotation_keeps_new_and_previous_only(world):
    user_id, ids = world.add_project(5, 33)
    world.mod.rotate_project_tokens()

    remaining = world.auth.ids_of(user_id)
    assert len(remaining) == 2
    assert ids[-1] in remaining  # the one Vault held before
    assert world.vaults[5].secrets["auth_token"] == f"jwt-{max(remaining)}"
    assert world.vaults[5].secrets["other"] == "kept"


def test_repeated_rotation_stays_at_two_and_retires_the_old_vault_token(world):
    user_id, ids = world.add_project(5, 1)
    for _ in range(3):
        world.mod.rotate_project_tokens()
    remaining = world.auth.ids_of(user_id)
    assert len(remaining) == 2
    assert ids[0] not in remaining  # a leaked token dies after two rotations


def test_rotation_order_is_add_then_vault_then_delete(world):
    world.add_project(5, 3)
    world.mod.rotate_project_tokens()
    kinds = [kind for kind, _ in world.auth.events]
    assert kinds[:2] == ["add", "vault"]
    assert set(kinds[2:]) == {"delete"}


def test_vault_and_newest_both_survive_when_they_differ(world):
    """Vault holds the oldest row (e.g. manual reset) while get_project_system_token hands out
    the newest; both may be in flight, so this one rotation keeps three rows."""
    user_id, ids = world.add_project(5, 4, vault_token="oldest")
    world.mod.rotate_project_tokens()
    remaining = world.auth.ids_of(user_id)
    assert remaining == [ids[0], ids[-1], max(remaining)]
    world.mod.rotate_project_tokens()
    assert len(world.auth.ids_of(user_id)) == 2  # converges on the next cycle


# --- keep_previous=False: incident hard cut ----------------------------------


def test_hard_cut_leaves_only_the_new_token(world):
    user_id, ids = world.add_project(5, 4)
    world.mod.rotate_project_tokens(keep_previous=False)
    remaining = world.auth.ids_of(user_id)
    assert len(remaining) == 1 and remaining[0] not in ids
    assert world.vaults[5].secrets["auth_token"] == f"jwt-{remaining[0]}"


def test_hard_cut_admin(world):
    world.auth.seed(ADMIN_USER, 3)
    world.vaults[None].secrets["auth_token"] = f"jwt-{max(world.auth.ids_of(ADMIN_USER))}"
    assert world.mod.rotate_admin_token(keep_previous=False) == 3
    assert len(world.auth.ids_of(ADMIN_USER)) == 1


def test_hard_cut_still_spares_named_and_expiring_tokens(world):
    user_id, _ = world.add_project(5, 2)
    named = world.auth.seed(user_id, 1, name="my-ci")[0]
    expiring = world.auth.seed(user_id, 1, expires="2030-01-01")[0]
    world.mod.rotate_project_tokens(keep_previous=False)
    assert {named, expiring} <= set(world.auth.ids_of(user_id))
    assert len(world.auth.ids_of(user_id)) == 3


# --- project_system_token: the single pick rule -------------------------------


def test_pick_is_newest_rotatable_and_matches_vault_after_rotation(world):
    world.add_project(5, 3)
    world.mod.rotate_project_tokens()
    assert world.mod.project_system_token(5) == world.vaults[5].secrets["auth_token"]


def test_pick_ignores_newer_named_and_expiring_tokens(world):
    """A higher-id 'api' token with an expiry, or any other name, must not win the pick."""
    user_id, ids = world.add_project(5, 2)
    world.auth.seed(user_id, 1, expires="2030-01-01")
    world.auth.seed(user_id, 1, name="my-ci")
    assert world.mod.current_token_id(user_id) == ids[-1]
    assert world.mod.project_system_token(5) == f"jwt-{ids[-1]}"


def test_pick_creates_when_missing_unless_told_not_to(world):
    user_id, _ = world.add_project(5, 0)
    assert world.mod.project_system_token(5, create_if_not_exists=False) is None
    assert world.auth.ids_of(user_id) == []
    token = world.mod.project_system_token(5)
    assert token == f"jwt-{world.auth.ids_of(user_id)[0]}"
    assert world.auth.tokens[world.auth.ids_of(user_id)[0]]["name"] == "api"


def test_pick_is_none_without_system_user(world):
    assert world.mod.project_system_token(77) is None
    assert world.auth.events == []


def test_unresolvable_vault_falls_back_to_highest_snapshot_id(world):
    user_id, ids = world.add_project(5, 4, vault_token="garbage")
    world.mod.rotate_project_tokens()
    remaining = world.auth.ids_of(user_id)
    assert ids[-1] in remaining and len(remaining) == 2


def test_failed_vault_write_deletes_nothing_and_loop_continues(world):
    user_a, ids_a = world.add_project(5, 4)
    user_b, _ = world.add_project(6, 4)
    world.vaults[5].fail_set = True

    stats = world.mod.rotate_project_tokens()

    assert set(ids_a) <= set(world.auth.ids_of(user_a))
    assert len(world.auth.ids_of(user_b)) == 2
    assert stats["failed"] == 1 and stats["rotated"] == 1
    assert world.mod.log.exceptions


def test_rotation_never_touches_named_expiring_or_concurrent_tokens(world):
    user_id, _ = world.add_project(5, 4)
    named = world.auth.seed(user_id, 1, name="my-ci")[0]
    expiring = world.auth.seed(user_id, 1, expires="2030-01-01")[0]
    real_add = world.auth.add_token

    def add_with_concurrent_insert(uid, name=""):
        world.concurrent = world.auth._insert(uid, "api")  # e.g. get_system_user_token racing
        return real_add(uid, name)

    world.auth.add_token = add_with_concurrent_insert
    world.mod.rotate_project_tokens()

    remaining = world.auth.ids_of(user_id)
    assert {named, expiring, world.concurrent} <= set(remaining)


def test_project_without_system_user_is_skipped(world):
    world.project_ids.append(77)
    world.add_project(5, 3)
    stats = world.mod.rotate_project_tokens()
    assert stats["skipped"] == 1 and stats["rotated"] == 1


def test_admin_rotation(world):
    world.auth.seed(ADMIN_USER, 34)
    world.vaults[None].secrets["auth_token"] = f"jwt-{max(world.auth.ids_of(ADMIN_USER))}"
    assert world.mod.rotate_admin_token() == 33
    assert len(world.auth.ids_of(ADMIN_USER)) == 2


# --- prune_system_tokens task ------------------------------------------------


def _backlog(world, projects=3, backlog=33):
    world.auth.seed(ADMIN_USER, 34)
    world.vaults[None].secrets["auth_token"] = f"jwt-{world.auth.ids_of(ADMIN_USER)[5]}"
    return {pid: world.add_project(pid, backlog) for pid in range(1, projects + 1)}


def test_prune_default_is_a_dry_run(world, prune):
    _backlog(world)
    before = dict(world.auth.tokens)
    log = prune()
    assert world.auth.tokens == before
    assert "would delete" in log.text
    assert "dry_run=True" in log.text


def test_prune_keeps_vault_token_and_newest(world, prune):
    projects = _backlog(world)
    admin_vault_id = world.auth.ids_of(ADMIN_USER)[5]
    admin_newest = world.auth.ids_of(ADMIN_USER)[-1]

    log = prune("dry_run=false")

    assert world.auth.ids_of(ADMIN_USER) == sorted({admin_vault_id, admin_newest})
    for user_id, ids in projects.values():
        assert world.auth.ids_of(user_id) == [ids[-1]]  # vault == newest: one row
    assert f"{32 + 3 * 32} token(s) deleted" in log.text


def test_prune_project_id_is_a_canary(world, prune):
    projects = _backlog(world)
    prune("dry_run=false,project_id=2")
    assert len(world.auth.ids_of(projects[2][0])) == 1
    assert len(world.auth.ids_of(projects[1][0])) == 33
    assert len(world.auth.ids_of(ADMIN_USER)) == 34  # admin is not part of a canary


def test_prune_limit_counts_pruned_projects_so_reruns_advance(world, prune):
    projects = _backlog(world, projects=4)
    prune("dry_run=false,limit=2")
    counts = [len(world.auth.ids_of(projects[pid][0])) for pid in (1, 2, 3, 4)]
    assert counts == [1, 1, 33, 33]

    prune("dry_run=false,limit=2")  # 1 and 2 are clean now, so 3 and 4 are next
    counts = [len(world.auth.ids_of(projects[pid][0])) for pid in (1, 2, 3, 4)]
    assert counts == [1, 1, 1, 1]


def test_prune_unresolvable_vault_keeps_newest_two(world, prune):
    user_id, ids = world.add_project(1, 10, vault_token="garbage")
    log = prune("dry_run=false,project_id=1")
    assert world.auth.ids_of(user_id) == ids[-2:]
    assert any("unresolvable" in w for w in log.warnings)


def test_prune_skips_users_with_two_or_fewer(world, prune):
    user_id, ids = world.add_project(1, 2, vault_token="oldest")
    prune("dry_run=false,project_id=1")
    assert world.auth.ids_of(user_id) == ids
    assert not [e for e in world.auth.events if e[0] == "delete"]


def test_prune_pauses_every_n_projects(world, prune):
    _backlog(world, projects=5, backlog=3)
    prune("dry_run=false,pause_every=2,pause_s=0.25")
    assert world.sleeps.count(0.25) == 2


def test_prune_rerun_is_a_noop(world, prune):
    _backlog(world)
    prune("dry_run=false")
    world.auth.events.clear()
    log = prune("dry_run=false")
    assert world.auth.events == []
    assert "0 token(s) deleted" in log.text


def test_prune_one_failing_project_does_not_stop_the_run(world, prune):
    projects = _backlog(world)
    real_list = world.auth.list_tokens

    def flaky(user_id=None, name=None):
        if user_id == projects[2][0]:
            raise RuntimeError("auth timeout")
        return real_list(user_id, name)

    world.auth.list_tokens = flaky
    log = prune("dry_run=false")
    assert len(world.auth.ids_of(projects[3][0])) == 1
    assert any("failed" in w for w in log.warnings)


@pytest.mark.parametrize("param", ["dry_run=maybe", "limit=abc", "dryrun=false", "pause_s=x"])
def test_prune_bad_params_are_refused_before_any_rpc(world, prune, param):
    _backlog(world)
    with pytest.raises(ValueError):
        prune(param)
    assert world.auth.events == []


def test_prune_logs_progress_within_a_large_backlog(world, prune):
    """A single 33k-token user took ~100s silently and looked hung in the UI."""
    world.mod.PROGRESS_EVERY = 10
    world.add_project(1, 35)
    log = prune("dry_run=false,project_id=1")
    assert "... 10 of 34 token(s) deleted" in log.text
    assert "... 30 of 34 token(s) deleted" in log.text


# --- recreate_project_tokens task param -------------------------------------


class RotateRpc:
    def __init__(self):
        self.calls = []

    def timeout(self, _seconds):
        return self

    def admin_rotate_tokens(self, **kwargs):
        self.calls.append(kwargs)


@pytest.fixture
def recreate(plugin_root, world, monkeypatch):
    tasks_package = types.ModuleType(TASKS_PACKAGE)
    tasks_package.__path__ = [str(plugin_root / "tasks")]
    logs_stub = types.ModuleType(f"{TASKS_PACKAGE}.logs")
    logs_stub.make_logger = StubMakeLogger
    monkeypatch.setitem(sys.modules, TASKS_PACKAGE, tasks_package)
    monkeypatch.setitem(sys.modules, f"{TASKS_PACKAGE}.logs", logs_stub)
    try:
        mod = importlib.import_module(f"{TASKS_PACKAGE}.project_tasks")
        rpc = RotateRpc()
        mod.context = types.SimpleNamespace(rpc_manager=rpc)

        def _run(param=None):
            kwargs = {} if param is None else {"param": param}
            mod.recreate_project_tokens(**kwargs)
            return rpc.calls
        yield _run
    finally:
        for name in (f"{TASKS_PACKAGE}.project_tasks", f"{TASKS_PACKAGE}.lifecycle_tasks"):
            sys.modules.pop(name, None)


@pytest.mark.parametrize("param,expected", [
    (None, True), ("", True), ("keep_previous=true", True),
    ("keep_previous=false", False), ('{"keep_previous": false}', False),
])
def test_recreate_keep_previous_param(recreate, param, expected):
    assert recreate(param) == [{"keep_previous": expected}]


@pytest.mark.parametrize("param", ["keep_previous=maybe", "revoke_previous=true"])
def test_recreate_bad_param_is_refused_before_rotating(recreate, param):
    with pytest.raises(ValueError):
        recreate(param)
