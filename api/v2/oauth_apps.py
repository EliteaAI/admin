"""OAuth apps (#7149): admin-managed clients for credentials of one provider (Microsoft Entra ID today).

Apps live in the Configurations plugin; this API is a thin authenticated shell over its
module methods, which re-check the Administration admin role. The client secret is
write-only: it is accepted on create and update and never returned.
"""
import flask
from tools import auth, api_tools, this, register_openapi

_VIEW_ROLES = {
    "administration": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
}
_WRITE_ROLES = _VIEW_ROLES


def _call(method_name, *args):
    module = this.for_module('configurations').module
    try:
        return getattr(module, method_name)(*args), None
    except PermissionError:
        return None, ({'error': 'Administration admin role is required'}, 403)
    except LookupError as exc:
        return None, ({'error': str(exc)}, 404)
    except Exception as exc:  # pylint: disable=W0718
        # The Configurations plugin reports invalid input as ConfigurationError(field, message)
        if callable(getattr(exc, 'to_dict', None)) and hasattr(exc, 'field'):
            return None, (exc.to_dict(), 400)
        raise


class AdminAPI(api_tools.APIModeHandler):
    @register_openapi(
        name='List OAuth apps',
        description='List the OAuth apps offered to credentials, each with its provider. '
                    'Client secrets are never returned, only client_secret_set.',
    )
    @auth.decorators.check_api({
        "permissions": ["configuration.oauth_apps.view"],
        "recommended_roles": _VIEW_ROLES,
    })
    def get(self, app_id: str = None):
        result, error = _call('oauth_apps_admin_list')
        if error:
            return error
        if app_id is not None:
            match = next((app for app in result if app['id'] == app_id), None)
            return (match, 200) if match else ({'error': 'OAuth app not found'}, 404)
        return {'total': len(result), 'rows': result}, 200

    @register_openapi(
        name='Create OAuth app',
        description='Add an OAuth app (name, provider (default microsoft_entra), client_id, client_secret, oauth_discovery_endpoint, '
                    'scopes per credential type, auto_refresh_token, is_default, enabled, allowed_project_ids).',
    )
    @auth.decorators.check_api({
        "permissions": ["configuration.oauth_apps.edit"],
        "recommended_roles": _WRITE_ROLES,
    })
    def post(self):
        result, error = _call('oauth_apps_admin_create', flask.request.get_json() or {})
        return error or (result, 201)

    @register_openapi(
        name='Update OAuth app',
        description='Update an OAuth app. Omit client_secret or send it empty to keep the stored secret. '
                    'The provider cannot be changed.',
        parameters=[{"name": "app_id", "in": "path", "schema": {"type": "string"}, "description": "App id."}],
    )
    @auth.decorators.check_api({
        "permissions": ["configuration.oauth_apps.edit"],
        "recommended_roles": _WRITE_ROLES,
    })
    def put(self, app_id: str):
        result, error = _call('oauth_apps_admin_update', app_id, flask.request.get_json() or {})
        return error or (result, 200)

    @register_openapi(
        name='Delete OAuth app',
        description='Delete an OAuth app and its secret. Credentials that use it ask the user to pick '
                    'another app or switch to Custom app.',
        parameters=[{"name": "app_id", "in": "path", "schema": {"type": "string"}, "description": "App id."}],
    )
    @auth.decorators.check_api({
        "permissions": ["configuration.oauth_apps.edit"],
        "recommended_roles": _WRITE_ROLES,
    })
    def delete(self, app_id: str):
        _, error = _call('oauth_apps_admin_delete', app_id)
        return error or ('', 204)


class API(api_tools.APIBase):
    url_params = ['<string:mode>', '<string:mode>/<string:app_id>']
    mode_handlers = {'administration': AdminAPI}
