"""#7340: membership notices use live settings, team-project snapshots and per-user inbox events."""
import importlib.util
import pathlib
import sys
import types

import pytest


PLUGIN_ROOT = pathlib.Path(__file__).resolve().parents[2]
HELPER = PLUGIN_ROOT / "utils" / "project_membership_notifications.py"


@pytest.fixture
def producer(monkeypatch):
    log_calls = []
    events = []
    failed_users = set()
    rpc_calls = []
    config = {}

    class FakeLog:
        def warning(self, message, *args, **kwargs):
            log_calls.append(("warning", message, args, kwargs))

        def exception(self, message, *args, **kwargs):
            log_calls.append(("exception", message, args, kwargs))

    rpc = types.SimpleNamespace(
        projects_get_project_kind=lambda project_id: rpc_calls.append(("kind", project_id)) or "team",
        project_get_by_id=lambda project_id: rpc_calls.append(("project", project_id))
        or {"id": project_id, "name": "Research [Archive]"},
    )
    manager = types.SimpleNamespace(timeout=lambda _seconds: rpc)

    def fire_event(event_name, payload):
        if payload["user_id"] in failed_users:
            raise RuntimeError("notification bus unavailable")
        events.append((event_name, payload))

    module = types.SimpleNamespace(context=types.SimpleNamespace(
        rpc_manager=manager,
        event_manager=types.SimpleNamespace(fire_event=fire_event),
    ))
    core = types.SimpleNamespace(module=types.SimpleNamespace(
        descriptor=types.SimpleNamespace(config=config),
    ))
    tools = types.ModuleType("tools")
    tools.this = types.SimpleNamespace(for_module=lambda name: core)
    pylon_tools = types.ModuleType("pylon.core.tools")
    pylon_tools.log = FakeLog()
    for name, value in (
        ("tools", tools),
        ("pylon", types.ModuleType("pylon")),
        ("pylon.core", types.ModuleType("pylon.core")),
        ("pylon.core.tools", pylon_tools),
    ):
        monkeypatch.setitem(sys.modules, name, value)

    spec = importlib.util.spec_from_file_location("admin_membership_notification_producer", HELPER)
    helper = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, helper)
    spec.loader.exec_module(helper)
    return types.SimpleNamespace(
        notify=helper.notify_project_membership_change,
        module=module,
        config=config,
        events=events,
        failed_users=failed_users,
        rpc_calls=rpc_calls,
        log_calls=log_calls,
    )


def test_added_notifications_use_defaults_exclude_the_actor_and_snapshot_project_name(producer):
    producer.notify(
        producer.module,
        42,
        [9, 1, 7, 9],
        "user_was_added_to_some_project_as_teammate",
        actor_id=1,
    )

    assert producer.rpc_calls == [("kind", 42), ("project", 42)]
    assert [event[1]["user_id"] for event in producer.events] == [9, 7]
    assert producer.events[0] == (
        "notifications_stream",
        {
            "project_id": 42,
            "user_id": 9,
            "event_type": "user_was_added_to_some_project_as_teammate",
            "meta": {
                "project_name": "Research [Archive]",
                "message": "You have been added to Research [Archive] project.",
            },
        },
    )


def test_removed_notifications_are_off_by_default_and_only_send_for_team_projects(producer):
    producer.notify(producer.module, 42, [9], "user_was_removed_from_project")
    assert producer.events == []

    producer.config["notifications"] = {"project_membership": {"on_removed": True}}
    producer.module.context.rpc_manager.timeout(5).projects_get_project_kind = lambda project_id: "personal"
    producer.notify(producer.module, 42, [9], "user_was_removed_from_project")
    assert producer.events == []


def test_invalid_flag_uses_the_default_and_logs_a_warning(producer):
    producer.config["notifications"] = {"project_membership": {"on_added": "false"}}

    producer.notify(
        producer.module,
        42,
        [9],
        "user_was_added_to_some_project_as_teammate",
        actor_id=1,
    )

    assert len(producer.events) == 1
    assert any(call[0] == "warning" for call in producer.log_calls)


def test_added_notifications_can_be_disabled_without_project_lookups(producer):
    producer.config["notifications"] = {"project_membership": {"on_added": False}}

    producer.notify(
        producer.module,
        42,
        [9],
        "user_was_added_to_some_project_as_teammate",
        actor_id=1,
    )

    assert producer.events == []
    assert producer.rpc_calls == []


def test_a_failed_recipient_does_not_prevent_other_notifications(producer):
    producer.config["notifications"] = {"project_membership": {"on_removed": True}}
    producer.failed_users.add(9)

    producer.notify(producer.module, 42, [9, 7], "user_was_removed_from_project")

    assert [event[1]["user_id"] for event in producer.events] == [7]
    assert any(call[0] == "exception" for call in producer.log_calls)
    assert all("email" not in str(call).lower() for call in producer.log_calls)
