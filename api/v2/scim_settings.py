""" SCIM settings (#5202): the Microsoft Entra OAuth app that reads group nesting from Graph.

GET            {graph_oauth_app_id, graph: last pull status}
PUT            {graph_oauth_app_id}   (null turns nesting off)
POST check     read nesting now with the selected app
"""
import flask
from tools import auth, api_tools, this, register_openapi  # pylint: disable=E0401

_ROLES = {"administration": {"super_admin": True, "admin": True, "viewer": False, "editor": False}}
_PERMISSION = {"permissions": ["admin.scim.manage"], "recommended_roles": _ROLES}


def _scim():
    return this.module.scim


class AdminAPI(api_tools.APIModeHandler):
    @register_openapi(name="Get SCIM settings", description="The Entra app used to read group nesting.")
    @auth.decorators.check_api(_PERMISSION)
    def get(self, action: str = None, **kwargs):
        scim = _scim()
        if scim is None:
            return {"error": "SCIM provisioning is not enabled"}, 404
        return {"graph_oauth_app_id": scim.graph_app_id(), "graph": scim.sync.graph_status()}, 200

    @register_openapi(name="Update SCIM settings", description="Select the Entra app that reads group nesting.")
    @auth.decorators.check_api(_PERMISSION)
    def put(self, action: str = None, **kwargs):
        scim = _scim()
        if scim is None:
            return {"error": "SCIM provisioning is not enabled"}, 404
        app_id = (flask.request.get_json(silent=True) or {}).get("graph_oauth_app_id")
        if app_id is not None and not isinstance(app_id, str):
            return {"error": "graph_oauth_app_id must be a string or null"}, 400
        scim.set_graph_app_id(app_id)
        return {"graph_oauth_app_id": scim.graph_app_id()}, 200

    @register_openapi(name="Check SCIM Graph access", description="POST check: read group nesting now.")
    @auth.decorators.check_api(_PERMISSION)
    def post(self, action: str = None, **kwargs):
        scim = _scim()
        if scim is None:
            return {"error": "SCIM provisioning is not enabled"}, 404
        if action != "check":
            return {"error": "Unknown action"}, 404
        result = scim.check_graph()
        if result["success"]:
            scim.request_sync()
        return result, 200


class API(api_tools.APIBase):  # pylint: disable=R0903
    url_params = ['<string:mode>', '<string:mode>/<string:action>']
    mode_handlers = {'administration': AdminAPI}
