""" Provisioned SCIM users (#5202): audit of what the IdP pushed. Platform admins only.

GET    users: IdP name, email, linked ELITEA account, status, direct groups, last change
"""
from tools import auth, api_tools, this, register_openapi  # pylint: disable=E0401

_ROLES = {"administration": {"super_admin": True, "admin": True, "viewer": False, "editor": False}}
_PERMISSION = {"permissions": ["admin.scim.manage"], "recommended_roles": _ROLES}


def _scim():
    return this.module.scim


class AdminAPI(api_tools.APIModeHandler):
    @register_openapi(name="List SCIM users", description="Users the IdP provisioned and their ELITEA accounts.")
    @auth.decorators.check_api(_PERMISSION)
    def get(self, **kwargs):
        scim = _scim()
        if scim is None:
            return {"error": "SCIM provisioning is not enabled"}, 404
        rows = scim.sync.users_overview()
        return {"total": len(rows), "rows": rows}, 200


class API(api_tools.APIBase):  # pylint: disable=R0903
    url_params = [
        '<string:mode>',
    ]
    mode_handlers = {'administration': AdminAPI}
