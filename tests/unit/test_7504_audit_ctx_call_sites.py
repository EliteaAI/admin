"""EL-7504: every pylon_main call that changes users, roles or memberships passes audit_ctx (AC-8).

auth_core records the event in the changing transaction, but only the caller knows who acted. A call
without audit_ctx records actor "unknown"; this inventory keeps new call sites from drifting there.
"""
import ast
import pathlib

import pytest

PLUGINS = pathlib.Path(__file__).resolve().parents[3]

MUTATORS = {
    "add_user", "update_user", "delete_user", "assign_user_to_role", "remove_user_from_role",
    "add_project_user_role", "delete_project_user_role", "update_project_user_roles",
    "delete_project_role", "delete_role", "record_first_login",
    "auth_add_user", "auth_update_user", "auth_delete_user", "auth_assign_user_to_role",
    "auth_remove_user_from_role",
    # pylon_main membership RPCs: they fall back to the request context, which is System off-request
    "admin_add_user_to_project", "admin_remove_users_from_project", "admin_update_roles_for_user",
    "update_roles_for_user", "add_user_to_project_or_create", "projects_scim_create", "projects_scim_set_suspended",
}
RECEIVERS = {"auth", "call", "rpc", "module"}

SCANNED = ["admin", "projects", "elitea_core", "support_assistant"]


def _calls(path):
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        func = node.func
        receiver = func.value
        name = receiver.attr if isinstance(receiver, ast.Attribute) else getattr(receiver, "id", None)
        if func.attr in MUTATORS and name in RECEIVERS:
            yield node


def _sites():
    for plugin in SCANNED:
        root = PLUGINS / plugin
        if not root.exists():
            continue
        for path in sorted(root.rglob("*.py")):
            if "tests" in path.parts:
                continue
            for node in _calls(path):
                yield f"{path.relative_to(PLUGINS)}:{node.lineno}", node


SITES = list(_sites())


def test_inventory_is_not_empty():
    assert len(SITES) > 10


@pytest.mark.parametrize("site, node", SITES, ids=[site for site, _ in SITES])
def test_call_passes_audit_ctx(site, node):
    assert any(keyword.arg == "audit_ctx" for keyword in node.keywords), site
