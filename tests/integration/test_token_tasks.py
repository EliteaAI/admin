"""Integration tests for tasks/token_tasks.py (issue #5262).

The task is thin, but what it says in the log is what an operator decides a
release on: a dry run must not read as if rows were written, a run that lost
some inserts to a concurrent login must not read as a failure, and an RPC that
raised must not leave a "done" line behind.
"""
import importlib
import sys
import types

import pytest

PACKAGE = "admin_tasks_under_test"


class RecordingLog:
    """Captures formatted messages the way the operator would read them."""

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

    def critical(self, message, *args):
        pass

    @property
    def text(self):
        return "\n".join(self.info_messages)


class StubMakeLogger:
    """Stands in for tasks/logs.py, which needs centry_logging at import."""

    instances = []

    def __enter__(self):
        log = RecordingLog()
        StubMakeLogger.instances.append(log)
        return log

    def __exit__(self, *exc_info):
        return False


class FakeRpc:
    """Mimics context.rpc_manager.timeout(n).auth_backfill_system_tokens(...)."""

    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error
        self.calls = []

    def timeout(self, _seconds):
        return self

    def auth_backfill_system_tokens(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.result


def result(**overrides):
    payload = {
        "dry_run": False,
        "users_total": 3,
        "already_present": 0,
        "missing": 3,
        "created": 3,
        "skipped_suspended": 0,
        "reserved_name_conflicts": 0,
    }
    payload.update(overrides)
    return payload


@pytest.fixture(scope="module")
def token_tasks(plugin_root):
    """Import the real task with .logs and tools.context replaced.

    A synthetic package is registered rather than loading the file directly,
    because the task imports `.logs`, which pulls centry_logging. Everything
    installed here is removed again on teardown so the stubs cannot leak into
    another test module.
    """
    import tools  # noqa: F401  (stubbed by run_tests.py)

    tasks_package = types.ModuleType(PACKAGE)
    tasks_package.__path__ = [str(plugin_root / "tasks")]

    logs_stub = types.ModuleType(f"{PACKAGE}.logs")
    logs_stub.make_logger = StubMakeLogger

    installed = {PACKAGE: tasks_package, f"{PACKAGE}.logs": logs_stub}
    sys.modules.update(installed)

    previous_context = getattr(tools, "context", None)
    tools.context = types.SimpleNamespace(rpc_manager=None)

    try:
        yield importlib.import_module(f"{PACKAGE}.token_tasks")
    finally:
        for name in list(installed) + [f"{PACKAGE}.token_tasks"]:
            sys.modules.pop(name, None)
        tools.context = previous_context


@pytest.fixture
def run(token_tasks):
    """Run the task against a canned RPC, returning (rpc, log)."""
    import tools  # noqa: F401

    def _run(param=None, **rpc_kwargs):
        rpc = FakeRpc(**rpc_kwargs)
        tools.context.rpc_manager = rpc
        StubMakeLogger.instances.clear()

        kwargs = {} if param is None else {"param": param}
        try:
            token_tasks.migrate_user_system_tokens(**kwargs)
        finally:
            log = StubMakeLogger.instances[-1]

        return rpc, log

    return _run


# --- dry run ---------------------------------------------------------------


def test_dry_run_param_reaches_the_rpc(run):
    rpc, _ = run(param="dry_run", result=result(dry_run=True, created=0))

    assert rpc.calls == [{"dry_run": True}]


def test_dry_run_does_not_claim_anything_was_created(run):
    _, log = run(param="dry_run", result=result(dry_run=True, created=0))

    assert "3 user(s) would get a token, none written" in log.text
    assert "Created" not in log.text


def test_no_param_is_a_real_run(run):
    rpc, log = run(result=result())

    assert rpc.calls == [{"dry_run": False}]
    assert "Created 3 token(s) of 3 missing" in log.text


@pytest.mark.parametrize("param", ["dry_run", "DRY_RUN", "  dry_run  "])
def test_the_flag_is_read_regardless_of_case_and_padding(run, param):
    rpc, _ = run(param=param, result=result(dry_run=True, created=0))

    assert rpc.calls == [{"dry_run": True}]


@pytest.mark.parametrize("param", [
    "not_dry_run",
    "dryrun",
    "dry-run",
    "dry_run=true",
    "dry_run please",
    "something_else",
])
def test_a_param_that_is_not_the_flag_is_refused(run, param):
    """Neither reading is safe to assume, so the task stops instead of writing."""
    with pytest.raises(ValueError, match="Unrecognized param"):
        run(param=param, result=result())


def test_a_refused_param_reaches_no_rpc(run):
    import tools  # noqa: F401

    with pytest.raises(ValueError):
        run(param="dryrun", result=result())

    assert tools.context.rpc_manager.calls == []


# --- reporting -------------------------------------------------------------


def test_a_lost_race_is_reported_but_not_an_error(run):
    """A login provisioned the user first; the task still succeeded."""
    _, log = run(result=result(created=1, missing=3))

    assert "Created 1 token(s) of 3 missing" in log.text
    assert "2 user(s) were provisioned elsewhere mid-run" in log.text
    assert log.exceptions == []


def test_a_complete_run_reports_no_race(run):
    _, log = run(result=result())

    assert "provisioned elsewhere" not in log.text


def test_totals_include_the_suspended_skip(run):
    _, log = run(result=result(
        users_total=4, already_present=1, missing=2, created=2,
        skipped_suspended=1,
    ))

    assert "4 total, 1 already had a token, 1 suspended and skipped" in log.text


def test_reserved_name_conflicts_are_warned_about(run):
    _, log = run(result=result(reserved_name_conflicts=2))

    assert any("reserved name" in warning for warning in log.warnings)


def test_no_warning_when_there_are_no_conflicts(run):
    _, log = run(result=result())

    assert log.warnings == []


# --- failure ---------------------------------------------------------------


def test_an_rpc_failure_propagates(run):
    """The operator has to be able to tell a backfill that ran from one that did not."""
    with pytest.raises(RuntimeError, match="boom"):
        run(result=None, error=RuntimeError("boom"))


def test_an_rpc_failure_is_logged_before_it_is_raised(run):
    with pytest.raises(RuntimeError):
        run(result=None, error=RuntimeError("boom"))

    log = StubMakeLogger.instances[-1]
    assert log.exceptions == ["Got exception, stopping task"]
    assert "Created" not in log.text
