"""Unit tests for #7242 - bulk delete of project data (chats).

Covers utils/project_data_delete.py, which needs no database or pylon.
"""
import importlib.util
import pathlib
import re
import sys
import types

import pytest


UTILS_PATH = pathlib.Path(__file__).resolve().parents[2] / "utils"
PACKAGE = "_admin_utils_7242"


def _load_utils():
    """Import the delete utils without a running pylon"""
    if "pylon.core.tools" not in sys.modules:
        tools = types.ModuleType("pylon.core.tools")
        tools.log = types.SimpleNamespace(
            info=lambda *a, **k: None, warning=lambda *a, **k: None,
            error=lambda *a, **k: None, exception=lambda *a, **k: None,
        )
        sys.modules.setdefault("pylon", types.ModuleType("pylon"))
        sys.modules.setdefault("pylon.core", types.ModuleType("pylon.core"))
        sys.modules["pylon.core.tools"] = tools
    #
    package = types.ModuleType(PACKAGE)
    package.__path__ = [str(UTILS_PATH)]
    sys.modules[PACKAGE] = package
    #
    modules = {}
    for name in ("chat_backup", "project_data_delete"):
        spec = importlib.util.spec_from_file_location(
            "{}.{}".format(PACKAGE, name), UTILS_PATH / "{}.py".format(name),
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        modules[name] = module
    return modules


MODULES = _load_utils()
cb = MODULES["chat_backup"]
pdd = MODULES["project_data_delete"]


# ---------- requested types ----------

def test_supported_types_in_processing_order():
    """ Applications before toolkits (agent-as-tool rows go with their agent),
        credentials last (after the toolkits that use them) """
    assert pdd.SUPPORTED_TYPES == (
        "chats", "agents", "pipelines", "skills", "toolkits", "mcps", "credentials",
    )


def test_parse_types_returns_processing_order():
    assert pdd.parse_types({"types": ["credentials", "chats", "toolkits", "agents"]}) == [
        "chats", "agents", "toolkits", "credentials",
    ]


def test_parse_types_accepts_chats():
    assert pdd.parse_types({"types": ["chats"]}) == ["chats"]


def test_parse_types_drops_duplicates():
    assert pdd.parse_types({"types": ["chats", "chats"]}) == ["chats"]


@pytest.mark.parametrize("payload", [
    None, {}, {"types": []}, {"types": "chats"}, {"types": ["prompts"]},
    {"types": ["chats", "artifacts"]}, {"types": [None]},
])
def test_parse_types_rejects_empty_or_unknown(payload):
    with pytest.raises(ValueError):
        pdd.parse_types(payload)


# ---------- visible scope ----------

def test_visible_chats_match_the_backup_scope():
    """ The count shown and the chats deleted are the chats a backup carries (spec Q3 / Q4) """
    assert pdd.visible_chat_ids_sql("p_3", 7) == cb.conversation_scope_sql("p_3", 7)


def test_visible_chats_leave_other_users_private_chats_out():
    sql = pdd.visible_chat_ids_sql("p_3", 7)
    assert "not is_private or author_id = 7" in sql


# ---------- kinds ----------

@pytest.mark.parametrize("tool_type, meta, kind", [
    ("github", {}, "toolkit"),
    ("github", None, "toolkit"),
    ("github", {"mcp": False}, "toolkit"),
    ("mcp", {}, "mcp"),
    ("remote_tool", {"mcp": True}, "mcp"),
    ("application", {}, None),
    ("application", {"mcp": True}, None),
])
def test_toolkit_kind(tool_type, meta, kind):
    assert pdd.toolkit_kind(tool_type, meta) == kind


@pytest.mark.parametrize("agent_types, kind", [
    (["react"], "agent"),
    (["openai", "react"], "agent"),
    (["react", "pipeline"], "pipeline"),
    (["pipeline"], "pipeline"),
    ([], "agent"),
])
def test_application_kind(agent_types, kind):
    assert pdd.application_kind(agent_types) == kind


@pytest.mark.parametrize("statuses, blocked", [
    (["draft"], False),
    (["draft", "unpublished", "rejected", "on_moderation", "user_approval"], False),
    (["draft", "published"], True),
    (["embedded"], True),
    ([], False),
])
def test_published_or_embedded_is_blocked(statuses, blocked):
    assert pdd.is_blocked(statuses) is blocked


def test_credentials_section():
    assert pdd.CREDENTIALS_SECTION == "credentials"


# ---------- authorization ----------

@pytest.mark.parametrize("has_permission, own_project, allowed", [
    (True, False, True),
    (False, True, True),
    (True, True, True),
    (False, False, False),
])
def test_authorized_by_admin_permission_or_ownership(has_permission, own_project, allowed):
    assert pdd.is_authorized(has_permission, own_project) is allowed


# ---------- outcome ----------

@pytest.mark.parametrize("results, status", [
    ({"chats": {"deleted": 3, "failed": 0}}, pdd.STATUS_SUCCESS),
    ({"chats": {"deleted": 0, "failed": 0}}, pdd.STATUS_SUCCESS),
    ({"chats": {"deleted": 2, "failed": 1}}, pdd.STATUS_PARTIAL),
    ({"chats": {"deleted": 0, "failed": 4}}, pdd.STATUS_FAILED),
    ({"agents": {"deleted": 2, "failed": 0, "skipped": 3}}, pdd.STATUS_SUCCESS),
    ({"agents": {"deleted": 0, "failed": 0, "skipped": 3}}, pdd.STATUS_SUCCESS),
    ({"chats": {"deleted": 4, "failed": 0}, "skills": {"deleted": 0, "failed": 1, "skipped": 1}},
     pdd.STATUS_PARTIAL),
])
def test_status_aggregation(results, status):
    assert pdd.aggregate_status(results) == status


# ---------- audit ----------

def _event(status=None, results=None):
    results = results or {"chats": {"deleted": 5, "failed": 1}}
    return pdd.build_audit_event(
        project_id=3, actor_user_id=7, types=["chats"], results=results,
        status=status or pdd.aggregate_status(results),
    )


def test_audit_event_identifies_actor_project_and_action():
    event = _event()
    assert event["event_type"] == "lifecycle"
    assert event["reason_code"] == "PROJECT_DATA_DELETED"
    assert event["project_id"] == 3
    assert event["caller_ref"] == "user:7"


def test_audit_event_carries_types_and_counts():
    assert _event()["target_ref"] == "chats=d5,f1,s0"


def test_audit_event_lists_every_type_with_skips():
    results = {
        "chats": {"deleted": 5, "failed": 0},
        "agents": {"deleted": 2, "failed": 0, "skipped": 1},
        "credentials": {"deleted": 3, "failed": 0, "skipped": 0},
    }
    event = pdd.build_audit_event(
        project_id=3, actor_user_id=7, types=["chats", "agents", "credentials"],
        results=results, status=pdd.aggregate_status(results),
    )
    assert event["target_ref"] == "chats=d5,f0,s0;agents=d2,f0,s1;credentials=d3,f0,s0"


def test_audit_target_ref_fits_with_every_type_and_large_counts():
    results = {name: {"deleted": 999999, "failed": 999999, "skipped": 999999} for name in pdd.SUPPORTED_TYPES}
    event = pdd.build_audit_event(
        project_id=3, actor_user_id=7, types=list(pdd.SUPPORTED_TYPES),
        results=results, status=pdd.aggregate_status(results),
    )
    assert len(event["target_ref"]) <= 256


@pytest.mark.parametrize("results, outcome", [
    ({"chats": {"deleted": 5, "failed": 0}}, "success"),
    ({"agents": {"deleted": 1, "failed": 0, "skipped": 2}}, "success"),
    ({"chats": {"deleted": 5, "failed": 1}}, "failed"),
    ({"chats": {"deleted": 0, "failed": 2}}, "failed"),
])
def test_audit_outcome(results, outcome):
    assert _event(results=results)["outcome"] == outcome


def test_audit_reason_code_is_valid():
    assert re.fullmatch(r"^[A-Z0-9_]+$", _event()["reason_code"])
