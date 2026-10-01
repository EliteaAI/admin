"""Integration tests for tasks/permission_tasks.py (issue #6874).

The task deletes grants platform-wide, so the safety properties matter more
than the plumbing: an empty param must only rehearse, an unknown param must
stop before any RPC, and DEAD_PERMISSIONS must never name a string that code
still checks - deleting one of those would silently revoke real access.
"""
import importlib
import pathlib
import re
import sys
import types

import pytest

PACKAGE = "admin_permission_tasks_under_test"


class RecordingLog:
    def __init__(self):
        self.info_messages = []
        self.exceptions = []

    @staticmethod
    def _format(message, args):
        return message % args if args else message

    def info(self, message, *args):
        self.info_messages.append(self._format(message, args))

    def exception(self, message, *args):
        self.exceptions.append(self._format(message, args))

    def warning(self, message, *args):
        pass

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


class FakeRpc:
    """Mimics context.rpc_manager.timeout(n).auth_delete_permissions_everywhere(...)."""

    def __init__(self, error=None):
        self.error = error
        self.calls = []

    def timeout(self, _seconds):
        return self

    def auth_delete_permissions_everywhere(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return {"dry_run": kwargs["dry_run"], "deleted": {"role_permission": 7, "project_role_permission": 2}}


@pytest.fixture(scope="module")
def permission_tasks(plugin_root):
    import tools  # noqa: F401  (stubbed by run_tests.py)

    tasks_package = types.ModuleType(PACKAGE)
    tasks_package.__path__ = [str(plugin_root / "tasks")]
    logs_stub = types.ModuleType(f"{PACKAGE}.logs")
    logs_stub.make_logger = StubMakeLogger

    installed = {PACKAGE: tasks_package, f"{PACKAGE}.logs": logs_stub}
    sys.modules.update(installed)
    previous_context = getattr(tools, "context", None)
    previous_log = getattr(tools, "log", None)
    tools.context = types.SimpleNamespace(rpc_manager=None)
    tools.log = RecordingLog()  # lifecycle_tasks needs tools.log at import

    try:
        yield importlib.import_module(f"{PACKAGE}.permission_tasks")
    finally:
        for name in list(installed) + [f"{PACKAGE}.permission_tasks", f"{PACKAGE}.lifecycle_tasks"]:
            sys.modules.pop(name, None)
        tools.context = previous_context
        tools.log = previous_log


@pytest.fixture
def run(permission_tasks):
    import tools  # noqa: F401

    def _run(param=None, **rpc_kwargs):
        rpc = FakeRpc(**rpc_kwargs)
        tools.context.rpc_manager = rpc
        StubMakeLogger.instances.clear()
        kwargs = {} if param is None else {"param": param}
        try:
            permission_tasks.cleanup_dead_permissions(**kwargs)
        finally:
            log = StubMakeLogger.instances[-1]
        return rpc, log

    return _run


# --- dry run is the default ------------------------------------------------


@pytest.mark.parametrize("param", [None, "", "dry_run=true", '{"dry_run": true}'])
def test_rehearses_unless_told_otherwise(run, param):
    rpc, log = run(param=param)

    assert rpc.calls[0]["dry_run"] is True
    assert "role_permission: would delete 7 row(s)" in log.text
    assert "nothing written" in log.text


@pytest.mark.parametrize("param", ["dry_run=false", '{"dry_run": false}'])
def test_dry_run_false_applies(run, param):
    rpc, log = run(param=param)

    assert rpc.calls[0]["dry_run"] is False
    assert "role_permission: deleted 7 row(s)" in log.text
    assert "nothing written" not in log.text


def test_full_allowlist_is_sent(run, permission_tasks):
    rpc, _ = run()

    assert rpc.calls[0]["permissions"] == list(permission_tasks.DEAD_PERMISSIONS)


def test_every_targeted_string_is_logged(run, permission_tasks):
    _, log = run()

    for permission in permission_tasks.DEAD_PERMISSIONS:
        assert f"  - {permission}" in log.info_messages


@pytest.mark.parametrize("param", ["project_id=3", "dry_run=maybe"])
def test_bad_param_stops_before_any_rpc(run, param):
    import tools  # noqa: F401

    rpc = FakeRpc()
    tools.context.rpc_manager = rpc
    with pytest.raises(ValueError):
        run(param=param)


def test_rpc_failure_is_reraised_and_logged(run):
    with pytest.raises(RuntimeError):
        run(error=RuntimeError("auth down"))

    assert StubMakeLogger.instances[-1].exceptions


# --- the allowlist never names a live permission ---------------------------

# Strings with exact checks today; they share prefixes with dead ones and must survive.
LIVE_PERMISSIONS = {
    "admin.auth.users", "admin.moderation",
    "configuration.roles", "configuration.users", "configuration.advanced",
    "configuration.service_descriptors", "configuration.litellm",
    "configuration.evaluation.platform_dimensions.view",
    "configuration.evaluation.platform_dimensions.create",
    "configuration.evaluation.platform_dimensions.edit",
    "configuration.evaluation.platform_dimensions.delete",
    "invites.bulkusers", "invites.bulkprojects",
    "migration.db", "migration.permissions", "modes.users",
    "models.chat.conversations.list",
    "projects.projects", "projects.projects.backup.download", "projects.projects.backup.full",
    "projects.projects.restore.apply", "projects.projects.restore.full",
    "runtime.plugins",
}


def test_no_live_permission_is_in_the_allowlist(permission_tasks):
    assert not set(permission_tasks.DEAD_PERMISSIONS) & LIVE_PERMISSIONS


def test_allowlist_has_no_duplicates(permission_tasks):
    assert len(set(permission_tasks.DEAD_PERMISSIONS)) == len(permission_tasks.DEAD_PERMISSIONS)


def test_no_sibling_plugin_registers_or_checks_a_dead_string(permission_tasks, plugin_root):
    """Scan every sibling plugin's Python for the dead strings as quoted literals.

    A hit means a plugin still registers or checks the string, so the startup
    seeding would re-create the rows this task deletes. Migrations are skipped:
    they record history, they do not check permissions.
    """
    plugins_dir = pathlib.Path(plugin_root).parent
    own_file = (pathlib.Path(plugin_root) / "tasks" / "permission_tasks.py").resolve()
    # "admin" is also the role name passed to every role RPC; scanning it is pure noise.
    scanned = [p for p in permission_tasks.DEAD_PERMISSIONS if p != "admin"]
    pattern = re.compile(r"""["'](%s)["']""" % "|".join(re.escape(p) for p in scanned))
    hits = []
    for path in plugins_dir.rglob("*.py"):
        parts = set(path.parts)
        if parts & {"migrations", "tests", "node_modules", "site-packages", "static"}:
            continue
        if path.resolve() == own_file:
            continue
        for lineno, line in enumerate(path.read_text(errors="ignore").splitlines(), 1):
            match = pattern.search(line)
            if match and re.search(r"permission|check_(api|slot)|has_access", line, re.I):
                hits.append(f"{path}:{lineno}: {match.group(1)}")
    assert hits == []
