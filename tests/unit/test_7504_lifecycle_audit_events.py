"""EL-7504: event builder and actor context in pylon_main (AC-6, AC-8, AC-20).

The builder mirrors auth_core's ``tools/lifecycle_audit.py``; the payload contract is shared, so
both sides are checked against the same key set here.
"""
import importlib
import pathlib
import sys
import types

import pytest

UTILS_PATH = pathlib.Path(__file__).resolve().parents[2] / "utils"
AUTH_CORE_TOOLS = pathlib.Path(__file__).resolve().parents[5] / "pylon_auth" / "plugins" / "auth_core" / "tools"


def _load():
    sys.path.insert(0, str(UTILS_PATH))
    try:
        return importlib.import_module("lifecycle_audit")
    finally:
        sys.path.remove(str(UTILS_PATH))


la = _load()

PAYLOAD_KEYS = {
    "event_id", "occurred_at", "event_type", "scope", "source", "result", "failure_reason", "imported",
    "actor_type", "actor_id", "actor_name", "actor_email", "request_id",
    "project_id", "project_name", "project_type", "user_id", "user_name", "user_email",
    "roles_before", "roles_after", "admin_access", "changes", "details",
}


def test_payload_has_the_contract_keys():
    event = la.events.build("project.renamed", la.events.SYSTEM_CTX, "project",
                            project={"id": 5, "name": "Beta", "type": "team"})
    assert set(event) == PAYLOAD_KEYS
    assert event["imported"] is False
    assert event["occurred_at"].endswith("+00:00")


def test_auth_core_builder_uses_the_same_keys():
    if not AUTH_CORE_TOOLS.exists():
        pytest.skip("auth_core checkout not present")
    source = (AUTH_CORE_TOOLS / "lifecycle_audit.py").read_text()
    for key in PAYLOAD_KEYS - {"project_name", "project_type"}:
        assert f'"{key}"' in source, key


@pytest.mark.parametrize("before, after, expected", [
    ([], ["admin"], "granted"),
    (["admin"], ["editor"], "revoked"),
    (["viewer"], ["editor"], None),
])
def test_project_admin_access(before, after, expected):
    event = la.events.build("project.member_role_changed", la.events.SYSTEM_CTX, "project",
                            roles_before=before, roles_after=after,
                            admin_roles=la.events.PROJECT_ADMIN_ROLES)
    assert event["admin_access"] == expected


def test_secret_shaped_keys_are_dropped_at_any_depth():
    event = la.events.build("project.created", dict(la.events.SYSTEM_CTX, token="t"), "project",
                            details={"api_key": "k", "nested": {"password": "p", "ok": 1}})
    assert event["details"] == {"nested": {"ok": 1}}
    assert "token" not in event


def test_project_type_from_name():
    assert la.events.project_type("project_user_42") == "private"
    assert la.events.project_type("Alpha") == "team"


# --- actor context (AC-8) -----------------------------------------------------------

def auth(type_, id_):
    return types.SimpleNamespace(type=type_, id=id_)


def test_ctx_for_ui_user():
    ctx = la.events.ctx_from_auth(auth("user", 7), user={"name": "Root", "email": "r@x"}, request_id="r1")
    assert ctx == {"actor_type": "user", "actor_id": 7, "actor_name": "Root", "actor_email": "r@x",
                   "source": "ui", "request_id": "r1"}


def test_ctx_for_api_token():
    ctx = la.events.ctx_from_auth(auth("token", 7))
    assert ctx["source"] == "api"
    assert ctx["actor_type"] == "user"


@pytest.mark.parametrize("value", [None, auth("public", None)])
def test_ctx_without_identity_is_system(value):
    ctx = la.events.ctx_from_auth(value)
    assert ctx["actor_type"] == "system"
    assert ctx["source"] == "system"


def test_ctx_for_task_executor_and_scheduled_job():
    assert la.events.ctx_for_task(5)["actor_id"] == 5
    assert la.events.ctx_for_task(5)["source"] == "api"
    assert la.events.ctx_for_task(None) == la.events.SYSTEM_CTX


def test_scim_ctx():
    ctx = la.events.SCIM_CTX
    assert ctx["actor_type"] == "service"
    assert ctx["source"] == "provisioning"
