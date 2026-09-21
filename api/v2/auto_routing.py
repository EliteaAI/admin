"""Platform Auto master/default settings; only Administration admins may use it."""
import flask
from tools import auth, api_tools, this, register_openapi


class AdminAPI(api_tools.APIModeHandler):
    @register_openapi(name='Get Auto model selection settings', description='Read the platform Auto master switch and project default.')
    @auth.decorators.check_api(['configuration.section'])
    def get(self):
        try:
            return this.for_module('configurations').module.auto_routing_platform_settings()
        except PermissionError:
            return {'error': 'Administration admin role is required'}, 403

    @register_openapi(name='Update Auto model selection settings', description='Set platform availability and the default for projects. No restart is required.')
    @auth.decorators.check_api(['configuration.section'])
    def put(self):
        values = flask.request.get_json()
        if not isinstance(values, dict):
            return {'error': 'Supply boolean available and project_default values'}, 400
        try:
            return this.for_module('configurations').module.auto_routing_platform_settings(values)
        except PermissionError:
            return {'error': 'Administration admin role is required'}, 403
        except ValueError:
            return {'error': 'Supply boolean available and project_default values'}, 400


class API(api_tools.APIBase):
    url_params = ['<string:mode>']
    mode_handlers = {'administration': AdminAPI}
