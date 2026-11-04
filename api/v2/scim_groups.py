""" Provisioned SCIM groups and their projects (#5202). Platform admins only.

GET                    groups: status, project, direct/effective members, nesting, last activity
POST   <group_id>/sync re-run project creation and the membership sync now
"""
from tools import auth, api_tools, this, register_openapi  # pylint: disable=E0401

_ROLES = {"administration": {"super_admin": True, "admin": True, "viewer": False, "editor": False}}
_PERMISSION = {"permissions": ["admin.scim.manage"], "recommended_roles": _ROLES}


def _scim():
    return this.module.scim


class AdminAPI(api_tools.APIModeHandler):
    @register_openapi(name="List SCIM groups", description="Groups the IdP provisioned and their projects.")
    @auth.decorators.check_api(_PERMISSION)
    def get(self, group_id: str = None, action: str = None, **kwargs):
        scim = _scim()
        if scim is None:
            return {"error": "SCIM provisioning is not enabled"}, 404
        rows = scim.sync.overview()
        if group_id is not None:
            row = next((r for r in rows if r["id"] == group_id), None)
            return (row, 200) if row else ({"error": "Group not found"}, 404)
        return {"total": len(rows), "rows": rows, "graph": scim.sync.graph_status()}, 200

    @register_openapi(name="Sync SCIM group", description="POST <group_id>/sync: sync projects and members now.")
    @auth.decorators.check_api(_PERMISSION)
    def post(self, group_id: str, action: str = None, **kwargs):
        scim = _scim()
        if scim is None:
            return {"error": "SCIM provisioning is not enabled"}, 404
        if action != "sync":
            return {"error": "Unknown action"}, 404
        if not any(r["id"] == group_id for r in scim.sync.overview()):
            return {"error": "Group not found"}, 404
        scim.request_sync(graph_pull=True, full=True)
        return {"scheduled": True}, 202


class API(api_tools.APIBase):  # pylint: disable=R0903
    url_params = [
        '<string:mode>',
        '<string:mode>/<string:group_id>',
        '<string:mode>/<string:group_id>/<string:action>',
    ]
    mode_handlers = {'administration': AdminAPI}
