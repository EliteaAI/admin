"""auth.local_permissions holds only exact registered strings (issue #6874).

It feeds the Roles matrix rows and the PUT allowlist (known_rows). Until 2023-04
has_access matched by prefix, so auth expanded every string into its parents
(`configuration`, `configuration.evaluation`, ...). The check became exact match
but the expansion stayed, leaving rows that grant nothing; the PUT filter would
also accept them. This pins the expansion as gone.

auth/module.py imports the whole pylon runtime, so the method is lifted out by AST
and executed against a fake module instead of importing the plugin.
"""
import ast
import pathlib
import types

import pytest


def _load_method(auth_module_path, name):
    tree = ast.parse(auth_module_path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.unparse(node)
    raise AssertionError(f"{name} not found in {auth_module_path}")


class FakePermissions:
    """Stand-in for models.pd.permissions.Permissions.parse_obj."""

    def __init__(self, permissions, recommended_roles):
        self.permissions = permissions
        self.recommended_roles = types.SimpleNamespace(dict=lambda: recommended_roles)

    @classmethod
    def parse_obj(cls, data):
        return cls(data.get("permissions", []), data.get("recommended_roles", {}))


@pytest.fixture
def auth_module(plugin_root):
    path = pathlib.Path(plugin_root).parent / "auth" / "module.py"
    namespace = {"Permissions": FakePermissions}
    exec(_load_method(path, "_create_template_permissions"), namespace)  # noqa: S102

    fake = types.SimpleNamespace(local_permissions=set(), inserted=[])
    fake.insert_permissions = fake.inserted.extend
    return fake, namespace["_create_template_permissions"], path


def test_registration_adds_only_the_exact_string(auth_module):
    fake, create, _ = auth_module

    create(fake, {
        "permissions": ["configuration.evaluation.platform_dimensions.view"],
        "recommended_roles": {"administration": {"admin": True, "viewer": False}},
    })

    # No `configuration`, `configuration.evaluation`, ... parents anymore.
    assert fake.local_permissions == {"configuration.evaluation.platform_dimensions.view"}
    assert fake.inserted == [("admin", "administration", "configuration.evaluation.platform_dimensions.view")]


def test_prefix_generators_are_gone(auth_module):
    _, _, path = auth_module
    source = path.read_text()

    assert "generate_permissions_from_string" not in source
    assert "def generate_permissions(" not in source
