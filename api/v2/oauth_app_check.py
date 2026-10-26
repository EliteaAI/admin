"""Test an OAuth app's client ID, secret and authority from the Admin Portal (#7149)."""
import flask
from tools import auth, api_tools, register_openapi

from .oauth_apps import _WRITE_ROLES, _call


class AdminAPI(api_tools.APIModeHandler):
    @register_openapi(
        name='Test OAuth app connection',
        description='Check client_id, client_secret and oauth_discovery_endpoint with the provider\'s sign-in. '
                    'Unsaved form values are used; with app_id an omitted secret uses the stored one.',
    )
    @auth.decorators.check_api({
        "permissions": ["configuration.oauth_apps.edit"],
        "recommended_roles": _WRITE_ROLES,
    })
    def post(self, app_id: str = None):
        result, error = _call('oauth_apps_admin_check', flask.request.get_json() or {}, app_id)
        return error or (result, 200)


class API(api_tools.APIBase):
    url_params = ['<string:mode>', '<string:mode>/<string:app_id>']
    mode_handlers = {'administration': AdminAPI}
