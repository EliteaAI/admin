"""#7149 Administration adapter for OAuth apps, with the Configurations owner mocked."""
import ast
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import Mock

import pytest

pytestmark = pytest.mark.unit


class ConfigurationError(Exception):
    def __init__(self, field, message):
        super().__init__(message)
        self.field, self.message = field, message

    def to_dict(self):
        return {'error': self.message, 'field': self.field}


@pytest.fixture
def adapter():
    path = Path(__file__).resolve().parents[1] / 'api/v2/oauth_apps.py'
    body = [n for n in ast.parse(path.read_text()).body
            if (isinstance(n, ast.ClassDef) and n.name == 'AdminAPI')
            or (isinstance(n, ast.FunctionDef) and n.name == '_call')]
    for node in body:
        for method in getattr(node, 'body', []):
            if isinstance(method, ast.FunctionDef):
                method.decorator_list = []
    flask = NS(request=Mock())
    owner = Mock()
    namespace = {'flask': flask, 'api_tools': NS(APIModeHandler=object),
                 'this': NS(for_module=lambda name: NS(module=owner))}
    exec(compile(ast.Module(body, []), str(path), 'exec'), namespace)
    return namespace['AdminAPI'](), owner, flask.request


def test_list_never_carries_a_secret_field_from_the_owner(adapter):
    api, owner, _ = adapter
    owner.oauth_apps_admin_list.return_value = [{'id': 'a', 'client_secret_set': True}]
    body, status = api.get()
    assert status == 200 and body['rows'] == [{'id': 'a', 'client_secret_set': True}]


def test_get_one_and_missing(adapter):
    api, owner, _ = adapter
    owner.oauth_apps_admin_list.return_value = [{'id': 'a'}]
    assert api.get('a') == ({'id': 'a'}, 200)
    assert api.get('b')[1] == 404


def test_create_and_update_forward_the_body(adapter):
    api, owner, request = adapter
    request.get_json.return_value = {'name': 'Contoso'}
    owner.oauth_apps_admin_create.return_value = {'id': 'a'}
    assert api.post() == ({'id': 'a'}, 201)
    owner.oauth_apps_admin_update.return_value = {'id': 'a'}
    assert api.put('a') == ({'id': 'a'}, 200)
    owner.oauth_apps_admin_update.assert_called_once_with('a', {'name': 'Contoso'})


def test_non_admins_are_refused(adapter):
    api, owner, request = adapter
    request.get_json.return_value = {}
    for method in ('oauth_apps_admin_list', 'oauth_apps_admin_create', 'oauth_apps_admin_delete'):
        getattr(owner, method).side_effect = PermissionError()
    assert api.get()[1] == 403
    assert api.post()[1] == 403
    assert api.delete('a')[1] == 403


def test_validation_errors_are_400(adapter):
    api, owner, request = adapter
    request.get_json.return_value = {}
    owner.oauth_apps_admin_create.side_effect = ConfigurationError('client_secret', 'Client secret is required')
    assert api.post() == ({'error': 'Client secret is required', 'field': 'client_secret'}, 400)


def test_delete(adapter):
    api, owner, _ = adapter
    assert api.delete('a') == ('', 204)
    owner.oauth_apps_admin_delete.side_effect = LookupError('OAuth app not found')
    assert api.delete('b')[1] == 404
