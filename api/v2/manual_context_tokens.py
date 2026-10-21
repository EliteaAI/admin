"""Platform toggle for manual Max Context Tokens (summarization testing); Administration admins only."""
import flask
from tools import auth, api_tools, this, register_openapi

PUT_ERROR = 'Supply a boolean enabled value'


class AdminAPI(api_tools.APIModeHandler):
    @register_openapi(name='Get manual Max Context Tokens setting', description='Read whether platform admins may set a manual summarization trigger per chat.')
    @auth.decorators.check_api(['configuration.section'])
    def get(self):
        try:
            return this.for_module('configurations').module.manual_context_tokens_platform_settings()
        except PermissionError:
            return {'error': 'Administration admin role is required'}, 403

    @register_openapi(name='Update manual Max Context Tokens setting', description='Allow or disallow platform admins to set a manual summarization trigger per chat.')
    @auth.decorators.check_api(['configuration.section'])
    def put(self):
        values = flask.request.get_json()
        if not isinstance(values, dict):
            return {'error': PUT_ERROR}, 400
        try:
            return this.for_module('configurations').module.manual_context_tokens_platform_settings(values)
        except PermissionError:
            return {'error': 'Administration admin role is required'}, 403
        except ValueError:
            return {'error': PUT_ERROR}, 400


class API(api_tools.APIBase):
    url_params = ['<string:mode>']
    mode_handlers = {'administration': AdminAPI}
