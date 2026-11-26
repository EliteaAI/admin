"""Scheduled evaluation Administration adapters, with the elitea_core RPCs mocked."""
import ast
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import Mock

import pytest
from werkzeug.datastructures import MultiDict

pytestmark = pytest.mark.unit

API_DIR = Path(__file__).resolve().parents[1] / 'api/v2'


def _module_body(path):
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
    return compile(ast.Module(body, []), str(path), 'exec')


def _load(filename, request):
    flask = NS(request=request, g=NS(auth=NS(id=7)))
    namespace = {'flask': flask, 'api_tools': NS(APIModeHandler=object), 'log': Mock()}
    # The sibling modules import the roles and the RPC guard from eval_auto.
    exec(_module_body(API_DIR / 'eval_auto.py'), namespace)
    exec(_module_body(API_DIR / filename), namespace)
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


class RpcTimeout(Exception):
    pass


@pytest.mark.parametrize('failure, status, reason', [
    (RpcTimeout('slow'), 504, 'timeout'),
    (RuntimeError('boom'), 502, 'rpc_error'),
])
def test_run_now_reports_a_failed_rpc(settings_api, failure, status, reason):
    api, rpc, _ = settings_api
    rpc.elitea_core_eval_auto_run_now.side_effect = failure
    body, code = api.post()
    assert code == status and body['reason'] == reason
    # Only a timeout leaves the job's fate unknown.
    assert body.get('job_may_have_started', False) is (status == 504)


def test_run_now_without_a_result_is_a_bad_gateway(settings_api):
    api, rpc, _ = settings_api
    rpc.elitea_core_eval_auto_run_now.return_value = None
    assert api.post() == ({'ok': False, 'reason': 'no_result'}, 502)


def test_get_and_put_report_a_failed_rpc(settings_api):
    api, rpc, request = settings_api
    rpc.elitea_core_eval_auto_get_config.side_effect = RpcTimeout()
    assert api.get() == ({'ok': False, 'reason': 'timeout'}, 504)
    request.get_json.return_value = {'max_concurrent_runs': 3}
    rpc.elitea_core_eval_auto_set_config.return_value = None
    assert api.put() == ({'ok': False, 'reason': 'no_result'}, 502)


def test_the_error_body_does_not_leak_the_exception_text(settings_api):
    api, rpc, _ = settings_api
    rpc.elitea_core_eval_auto_get_config.side_effect = RuntimeError('postgresql://user:secret@db')
    assert 'secret' not in str(api.get())


def test_list_defaults(items_api):
    api, rpc, _ = items_api
    rpc.elitea_core_eval_auto_list.return_value = {'total': 0, 'items': [], 'job': None}
    assert api.get() == ({'total': 0, 'items': [], 'job': None}, 200)
    rpc.elitea_core_eval_auto_list.assert_called_once_with(
        project_id=None, status=None, reason=None, mode=None, search=None, limit=50, offset=0)


def test_list_forwards_filters(items_api):
    api, rpc, request = items_api
    request.args = MultiDict({'project_id': '2', 'status': 'not_evaluated', 'reason': 'NO_TRAFFIC',
                              'mode': 'history', 'search': ' bot ', 'limit': '25', 'offset': '50'})
    api.get()
    rpc.elitea_core_eval_auto_list.assert_called_once_with(
        project_id=2, status='not_evaluated', reason='NO_TRAFFIC', mode='history', search='bot',
        limit=25, offset=50)


@pytest.mark.parametrize('args', [
    {'project_id': 'x'}, {'project_id': '0'}, {'status': 'bogus'},
    {'limit': '0'}, {'limit': '1001'}, {'limit': 'x'}, {'offset': '-1'},
    {'reason': 'bogus'}, {'mode': 'hybrid'}, {'search': 'x' * 201},
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


def _auto_registration():
    """The recommended roles module.py registers the scheduled evaluation permissions with."""
    tree = ast.parse((Path(__file__).resolve().parents[1] / 'module.py').read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, 'attr', None) == 'register_permissions':
            try:
                spec = ast.literal_eval(node.args[0])
            except ValueError:
                continue
            if any(name.startswith('configuration.evaluation.auto.') for name in spec['permissions']):
                return spec
    return None


def test_permissions_are_admin_only():
    spec = _auto_registration()
    assert sorted(spec['permissions']) == [f'configuration.evaluation.auto.{action}' for action in ('edit', 'run', 'view')]
    # No project-mode grant, and neither editors nor viewers get platform-wide spend or cross-tenant data.
    assert spec['recommended_roles'] == {
        'administration': {'super_admin': True, 'admin': True, 'viewer': False, 'editor': False},
    }


def test_endpoints_check_the_same_roles(settings_api):
    _, _, request = settings_api
    _, _, namespace = _load('eval_auto.py', request)
    assert namespace['_AUTO_VIEW_ROLES'] == namespace['_AUTO_WRITE_ROLES'] == _auto_registration()['recommended_roles']


def test_dataset_resync_reports_a_timeout(dataset_api):
    api, rpc, _ = dataset_api
    rpc.elitea_core_eval_auto_resync_platform_dataset.side_effect = RpcTimeout()
    assert api.post() == ({'ok': False, 'reason': 'timeout'}, 504)


def test_dataset_put_without_a_result_is_a_bad_gateway(dataset_api):
    api, rpc, request = dataset_api
    request.get_json.return_value = {'probes': ['Hi']}
    rpc.elitea_core_eval_auto_set_platform_probes.return_value = None
    assert api.put()[1] == 502


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


@pytest.fixture
def consents_api():
    request = Mock()
    api, rpc, _ = _load('eval_auto_history_consents.py', request)
    return api, rpc


def test_history_consents_lists_the_opted_in_projects(consents_api):
    api, rpc = consents_api
    listing = {'total': 1, 'projects': [{'project_id': 4, 'name': 'Support', 'in_scope': True}]}
    rpc.elitea_core_eval_auto_history_consents.return_value = listing
    assert api.get() == (listing, 200)


def test_history_consents_reports_a_timeout(consents_api):
    api, rpc = consents_api
    rpc.elitea_core_eval_auto_history_consents.side_effect = RpcTimeout()
    assert api.get() == ({'ok': False, 'reason': 'timeout'}, 504)


def test_history_consents_need_the_view_permission():
    source = (API_DIR / 'eval_auto_history_consents.py').read_text()
    assert '"configuration.evaluation.auto.view"' in source
    assert 'recommended_roles": _AUTO_VIEW_ROLES' in source
