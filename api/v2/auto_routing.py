"""Platform Auto master/default settings; only Administration admins may use it."""
import flask
from tools import auth, api_tools, this, register_openapi

PUT_ERROR = 'Supply boolean available and project_default values and an optional classifier ({name, project_id} or null)'


def _valid_classifier(value):
    """The optional default classifier is a deployment reference or null (same shape as the Configurations plugin)."""
    if value is None:
        return True
    return (isinstance(value, dict) and set(value) == {'name', 'project_id'}
            and isinstance(value['name'], str) and 0 < len(value['name']) <= 512
            and type(value['project_id']) is int and value['project_id'] > 0)


class AdminAPI(api_tools.APIModeHandler):
    @register_openapi(name='Get Auto model selection settings', description='Read the platform Auto master switch, project default and default classifier, with the classifier options.')
    @auth.decorators.check_api(['configuration.section'])
    def get(self):
        try:
            return this.for_module('configurations').module.auto_routing_platform_settings()
        except PermissionError:
            return {'error': 'Administration admin role is required'}, 403

    @register_openapi(name='Update Auto model selection settings', description='Set platform availability, the default for projects and the optional default classifier ({name, project_id} or null). No restart is required.')
    @auth.decorators.check_api(['configuration.section'])
    def put(self):
        values = flask.request.get_json()
        if not isinstance(values, dict) or not _valid_classifier(values.get('classifier')):
            return {'error': PUT_ERROR}, 400
        try:
            return this.for_module('configurations').module.auto_routing_platform_settings(values)
        except PermissionError:
            return {'error': 'Administration admin role is required'}, 403
        except ValueError:
            return {'error': PUT_ERROR}, 400
        except Exception as exc:  # pylint: disable=W0718
            # The Configurations plugin reports a rejected classifier as ConfigurationError(field, message)
            if callable(getattr(exc, 'to_dict', None)) and hasattr(exc, 'field'):
                return exc.to_dict(), 400
            raise


class API(api_tools.APIBase):
    url_params = ['<string:mode>']
    mode_handlers = {'administration': AdminAPI}
