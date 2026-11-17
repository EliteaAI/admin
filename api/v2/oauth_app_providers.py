"""OAuth app providers and their credential types' scope catalogs for the Admin Portal (#7327).

The Configurations plugin reads labels, scope lists, defaults and flags from the credential
schemas, so the app dialog renders whatever the SDK offers without naming credential types.
"""
from tools import auth, api_tools, register_openapi

from .oauth_apps import _VIEW_ROLES, _call


class AdminAPI(api_tools.APIModeHandler):
    @register_openapi(
        name='List OAuth app providers',
        description='Providers an OAuth app can belong to; for each credential type the label, the scopes '
                    'its credential offers (with descriptions and flags such as admin_consent), the default '
                    'scopes and whether the type is opt-in.',
    )
    @auth.decorators.check_api({
        "permissions": ["configuration.oauth_apps.view"],
        "recommended_roles": _VIEW_ROLES,
    })
    def get(self):
        result, error = _call('oauth_apps_admin_providers')
        return error or ({'total': len(result), 'rows': result}, 200)


class API(api_tools.APIBase):
    url_params = ['<string:mode>']
    mode_handlers = {'administration': AdminAPI}
