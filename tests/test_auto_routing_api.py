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
    body = [n for n in ast.parse(path.read_text()).body
            if (isinstance(n, ast.ClassDef) and n.name == 'AdminAPI') or (isinstance(n, ast.FunctionDef) and n.name == '_valid_classifier')
            or (isinstance(n, ast.Assign) and n.targets[0].id == 'PUT_ERROR')]
    for node in body:
        for method in getattr(node, 'body', []):
            if isinstance(method, ast.FunctionDef):
                method.decorator_list = []
    flask = NS(request=Mock())
    owner = Mock()
    namespace = {'flask': flask, 'api_tools': NS(APIModeHandler=object),
        'this': NS(for_module=lambda name: NS(module=NS(auto_routing_platform_settings=owner)))}
    exec(compile(ast.Module(body, []), str(path), 'exec'), namespace)
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


VALID_REF = {'name': 'gpt-5.6-luna', 'project_id': 2}


@pytest.mark.parametrize('classifier', [VALID_REF, None])
def test_classifier_is_forwarded_to_owner(adapter, classifier):
    api, owner, app = adapter
    body = {'available': True, 'project_default': False, 'classifier': classifier}
    owner.return_value = {**body, 'classifier_options': [], 'can_manage': True}
    app.get_json.return_value = body
    assert api.put() == owner.return_value
    owner.assert_called_once_with(body)


def test_body_without_classifier_is_forwarded_unchanged(adapter):
    api, owner, app = adapter
    app.get_json.return_value = {'available': True, 'project_default': True}
    api.put()
    owner.assert_called_once_with({'available': True, 'project_default': True})


@pytest.mark.parametrize('classifier', [
    'gpt-5.6-luna', [], {}, {'name': 'x'}, {'project_id': 2},
    {'name': '', 'project_id': 2}, {'name': 3, 'project_id': 2}, {'name': 'x' * 513, 'project_id': 2},
    {'name': 'x', 'project_id': '2'}, {'name': 'x', 'project_id': True}, {'name': 'x', 'project_id': 0},
    {'name': 'x', 'project_id': -1}, {'name': 'x', 'project_id': 2, 'extra': 1},
])
def test_malformed_classifier_rejected_before_owner(adapter, classifier):
    api, owner, app = adapter
    app.get_json.return_value = {'available': True, 'project_default': True, 'classifier': classifier}
    body, status = api.put()
    assert status == 400 and 'classifier' in body['error']
    owner.assert_not_called()


def test_owner_value_error_returns_400_naming_classifier(adapter):
    api, owner, app = adapter
    owner.side_effect = ValueError('Model x is not available to this project')
    app.get_json.return_value = {'available': True, 'project_default': True, 'classifier': VALID_REF}
    body, status = api.put()
    assert status == 400 and 'classifier' in body['error']


def test_rejected_classifier_error_is_returned_as_400(adapter):
    api, owner, app = adapter

    class ConfigurationError(Exception):
        field = 'classifier'

        def to_dict(self):
            return {'error': 'Model x is not available to this project', 'field': 'classifier'}

    owner.side_effect = ConfigurationError()
    app.get_json.return_value = {'available': True, 'project_default': True, 'classifier': VALID_REF}
    assert api.put() == ({'error': 'Model x is not available to this project', 'field': 'classifier'}, 400)


def test_unexpected_owner_error_is_not_swallowed(adapter):
    api, owner, app = adapter
    owner.side_effect = RuntimeError('boom')
    app.get_json.return_value = {'available': True, 'project_default': True}
    with pytest.raises(RuntimeError):
        api.put()


def test_get_returns_classifier_fields_from_owner(adapter):
    api, owner, _ = adapter
    owner.return_value = {'available': True, 'project_default': False, 'classifier': VALID_REF,
        'classifier_options': [{'name': 'gpt-5.6-luna', 'project_id': 2, 'display_name': 'Luna', 'low_tier': True}], 'can_manage': True}
    assert api.get() == owner.return_value
