"""Actual Administration HTTP adapter, with owner authentication/persistence mocked."""
import ast
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import Mock
import pytest

pytestmark = pytest.mark.unit


@pytest.fixture
def adapter():
    path = Path(__file__).resolve().parents[1]/'api/v2/auto_routing.py'
    node = next(n for n in ast.parse(path.read_text()).body if isinstance(n, ast.ClassDef) and n.name == 'AdminAPI')
    for method in node.body:
        if isinstance(method, ast.FunctionDef):
            method.decorator_list = []
    flask = NS(request=Mock())
    owner = Mock()
    namespace = {'flask': flask, 'api_tools': NS(APIModeHandler=object),
        'this': NS(for_module=lambda name: NS(module=NS(auto_routing_platform_settings=owner)))}
    exec(compile(ast.Module([node], []), str(path), 'exec'), namespace)
    return namespace['AdminAPI'](), owner, flask.request


def test_global_toggle_write_uses_configuration_owner(adapter):
    api, owner, app = adapter
    owner.return_value = {'available': False, 'project_default': True}
    app.get_json.return_value = {'available': False, 'project_default': True}
    assert api.put() == owner.return_value
    owner.assert_called_once_with({'available': False, 'project_default': True})


def test_unauthorized_admin_adapter_cannot_write(adapter):
    api, owner, app = adapter;owner.side_effect = PermissionError()
    app.get_json.return_value = {'available': True, 'project_default': True}
    assert api.put()[1] == 403
    assert api.get()[1] == 403


def test_malformed_body_rejected_before_owner(adapter):
    api, owner, app = adapter
    app.get_json.return_value = ['invalid']
    assert api.put()[1] == 400
    owner.assert_not_called()
