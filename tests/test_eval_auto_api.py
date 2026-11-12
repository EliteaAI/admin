"""Scheduled evaluation Administration adapters, with the elitea_core RPCs mocked."""
import ast
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import Mock

import pytest
from werkzeug.datastructures import MultiDict

pytestmark = pytest.mark.unit

API_DIR = Path(__file__).resolve().parents[1] / 'api/v2'


def _load(filename, request):
    path = API_DIR / filename
    tree = ast.parse(path.read_text())
    body = []
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        if isinstance(node, ast.ClassDef) and node.name == 'API':
            continue
        for method in getattr(node, 'body', []):
            if isinstance(method, ast.FunctionDef):
                # Keep @property (the _rpc accessor); drop the auth/openapi wrappers.
                method.decorator_list = [d for d in method.decorator_list if getattr(d, 'id', None) == 'property']
        body.append(node)
    flask = NS(request=request, g=NS(auth=NS(id=7)))
    namespace = {'flask': flask, 'api_tools': NS(APIModeHandler=object), '_VIEW_ROLES': {}, '_WRITE_ROLES': {}}
    exec(compile(ast.Module(body, []), str(path), 'exec'), namespace)
    rpc = Mock()
    api = namespace['AdminAPI']()
    api.module = NS(context=NS(rpc_manager=NS(call=rpc, timeout=lambda seconds: rpc)))
    return api, rpc, namespace


@pytest.fixture
def settings_api():
    request = Mock()
    api, rpc, _ = _load('eval_auto.py', request)
    return api, rpc, request


@pytest.fixture
def items_api():
    request = NS(args=MultiDict())
    api, rpc, namespace = _load('eval_auto_items.py', request)
    return api, rpc, request


def test_get_returns_the_effective_settings(settings_api):
    api, rpc, _ = settings_api
    rpc.elitea_core_eval_auto_get_config.return_value = {'max_concurrent_runs': 2, 'fail_threshold': 50.0}
    assert api.get() == ({'max_concurrent_runs': 2, 'fail_threshold': 50.0}, 200)


def test_put_forwards_the_body_and_the_editor(settings_api):
    api, rpc, request = settings_api
    request.get_json.return_value = {'max_concurrent_runs': 3}
    rpc.elitea_core_eval_auto_set_config.return_value = {'ok': True, 'settings': {'max_concurrent_runs': 3}}
    assert api.put() == ({'max_concurrent_runs': 3}, 200)
    rpc.elitea_core_eval_auto_set_config.assert_called_once_with({'max_concurrent_runs': 3}, user_id=7)


def test_put_reports_a_refused_value(settings_api):
    api, rpc, request = settings_api
    request.get_json.return_value = {'project_scope_mode': 'bogus'}
    refused = {'ok': False, 'error': 'invalid value for: project_scope_mode'}
    rpc.elitea_core_eval_auto_set_config.return_value = refused
    assert api.put() == (refused, 400)


@pytest.mark.parametrize('body', [None, [], 'text', 3])
def test_put_rejects_a_body_that_is_not_an_object(settings_api, body):
    api, rpc, request = settings_api
    request.get_json.return_value = body
    assert api.put()[1] == 400
    rpc.elitea_core_eval_auto_set_config.assert_not_called()


def test_run_now_returns_the_job(settings_api):
    api, rpc, _ = settings_api
    rpc.elitea_core_eval_auto_run_now.return_value = {'started': True, 'job_id': 4, 'counters': {'queued': 2}}
    assert api.post() == ({'started': True, 'job_id': 4, 'counters': {'queued': 2}}, 200)
    rpc.elitea_core_eval_auto_run_now.assert_called_once_with(user_id=7)


def test_run_now_while_a_job_runs_is_a_conflict(settings_api):
    api, rpc, _ = settings_api
    rpc.elitea_core_eval_auto_run_now.return_value = {'started': False, 'reason': 'job_running', 'job_id': 4}
    body, status = api.post()
    assert status == 409 and body['reason'] == 'job_running'


def test_list_defaults(items_api):
    api, rpc, _ = items_api
    rpc.elitea_core_eval_auto_list.return_value = {'total': 0, 'items': [], 'job': None}
    assert api.get() == ({'total': 0, 'items': [], 'job': None}, 200)
    rpc.elitea_core_eval_auto_list.assert_called_once_with(
        project_id=None, status=None, reason=None, search=None, limit=50, offset=0)


def test_list_forwards_filters(items_api):
    api, rpc, request = items_api
    request.args = MultiDict({'project_id': '2', 'status': 'not_evaluated', 'reason': 'TIMEOUT',
                              'search': ' bot ', 'limit': '25', 'offset': '50'})
    api.get()
    rpc.elitea_core_eval_auto_list.assert_called_once_with(
        project_id=2, status='not_evaluated', reason='TIMEOUT', search='bot', limit=25, offset=50)


@pytest.mark.parametrize('args', [
    {'project_id': 'x'}, {'project_id': '0'}, {'status': 'bogus'},
    {'limit': '0'}, {'limit': '1001'}, {'limit': 'x'}, {'offset': '-1'},
    {'reason': 'bogus'}, {'search': 'x' * 201},
])
def test_list_rejects_bad_filters(items_api, args):
    api, rpc, request = items_api
    request.args = MultiDict(args)
    assert api.get()[1] == 400
    rpc.elitea_core_eval_auto_list.assert_not_called()


def test_history_for_one_agent(items_api):
    api, rpc, _ = items_api
    rpc.elitea_core_eval_auto_history.return_value = {'total': 31, 'rows': [{'id': 1}, {'id': 2}]}
    assert api.get(2, 11) == ({'total': 31, 'rows': [{'id': 1}, {'id': 2}]}, 200)
    rpc.elitea_core_eval_auto_history.assert_called_once_with(2, 11, limit=20)


@pytest.mark.parametrize('limit', ['x', '0', '201'])
def test_history_rejects_a_bad_limit(items_api, limit):
    api, rpc, request = items_api
    request.args = MultiDict({'limit': limit})
    assert api.get(2, 11)[1] == 400
    rpc.elitea_core_eval_auto_history.assert_not_called()


def test_permissions_are_registered():
    source = (Path(__file__).resolve().parents[1] / 'module.py').read_text()
    for action in ('view', 'edit', 'run'):
        assert f'"configuration.evaluation.auto.{action}"' in source


@pytest.fixture
def dataset_api():
    request = Mock()
    api, rpc, _ = _load('eval_auto_dataset.py', request)
    return api, rpc, request


def test_dataset_get_returns_the_probes(dataset_api):
    api, rpc, _ = dataset_api
    rpc.elitea_core_eval_auto_get_platform_dataset.return_value = {'probes': ['Hi'], 'customized': False}
    assert api.get() == ({'probes': ['Hi'], 'customized': False}, 200)


def test_dataset_put_forwards_the_probes(dataset_api):
    api, rpc, request = dataset_api
    request.get_json.return_value = {'probes': ['Hi', 'Bye']}
    rpc.elitea_core_eval_auto_set_platform_probes.return_value = {'ok': True, 'probes': ['Hi', 'Bye']}
    assert api.put()[1] == 200
    rpc.elitea_core_eval_auto_set_platform_probes.assert_called_once_with(['Hi', 'Bye'])


@pytest.mark.parametrize('body', [None, [], {}, {'probes': 'Hi'}])
def test_dataset_put_rejects_a_body_without_a_probe_list(dataset_api, body):
    api, rpc, request = dataset_api
    request.get_json.return_value = body
    assert api.put()[1] == 400
    rpc.elitea_core_eval_auto_set_platform_probes.assert_not_called()


def test_dataset_put_reports_a_refused_list(dataset_api):
    api, rpc, request = dataset_api
    request.get_json.return_value = {'probes': []}
    rpc.elitea_core_eval_auto_set_platform_probes.return_value = {'ok': False, 'error': 'at least one probe is required'}
    assert api.put() == ({'ok': False, 'error': 'at least one probe is required'}, 400)


def test_dataset_post_resyncs_the_copies(dataset_api):
    api, rpc, _ = dataset_api
    rpc.elitea_core_eval_auto_resync_platform_dataset.return_value = {'ok': True, 'updated_datasets': 3, 'failures': []}
    assert api.post() == ({'ok': True, 'updated_datasets': 3, 'failures': []}, 200)


def test_dataset_post_reports_a_refused_resync(dataset_api):
    api, rpc, _ = dataset_api
    refused = {'ok': False, 'error': 'the platform dataset has no active probes'}
    rpc.elitea_core_eval_auto_resync_platform_dataset.return_value = refused
    assert api.post() == (refused, 409)
