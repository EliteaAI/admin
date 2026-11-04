""" SCIM tokens (#5202): issue (shown once), rotate, revoke. Platform admins only. """
import flask
from tools import auth, api_tools, this, register_openapi  # pylint: disable=E0401

from ...utils.scim.protocol import ScimError

_ROLES = {"administration": {"super_admin": True, "admin": True, "viewer": False, "editor": False}}
_PERMISSION = {"permissions": ["admin.scim.manage"], "recommended_roles": _ROLES}


def _scim():
    return this.module.scim


class AdminAPI(api_tools.APIModeHandler):
    @register_openapi(name="List SCIM tokens", description="SCIM tokens with their last 4 characters and usage.")
    @auth.decorators.check_api(_PERMISSION)
    def get(self, token_id: int = None, **kwargs):
        scim = _scim()
        if scim is None:
            return {"error": "SCIM provisioning is not enabled"}, 404
        rows = scim.service.list_tokens()
        return {"total": len(rows), "rows": rows, "base_url": scim.base_url()}, 200

    @register_openapi(
        name="Create or rotate SCIM token",
        description="Without token_id: issue a token (name). With token_id: revoke it and issue a replacement. "
                    "The token is returned only in this response.",
    )
    @auth.decorators.check_api(_PERMISSION)
    def post(self, token_id: int = None, **kwargs):
        scim = _scim()
        if scim is None:
            return {"error": "SCIM provisioning is not enabled"}, 404
        try:
            if token_id is not None:
                return scim.service.rotate_token(token_id, created_by=flask.g.auth.id), 201
            name = str((flask.request.get_json(silent=True) or {}).get("name") or "").strip()
            if not name:
                return {"error": "name is required"}, 400
            return scim.service.create_token(name, created_by=flask.g.auth.id), 201
        except ScimError as exc:
            return {"error": exc.detail}, exc.status

    @register_openapi(name="Revoke SCIM token", description="Revoke a SCIM token; the IdP is refused from then on.")
    @auth.decorators.check_api(_PERMISSION)
    def delete(self, token_id: int, **kwargs):
        scim = _scim()
        if scim is None:
            return {"error": "SCIM provisioning is not enabled"}, 404
        try:
            scim.service.revoke_token(token_id, revoked_by=flask.g.auth.id)
        except ScimError as exc:
            return {"error": exc.detail}, exc.status
        return None, 204


class API(api_tools.APIBase):  # pylint: disable=R0903
    url_params = ['<string:mode>', '<string:mode>/<int:token_id>']
    mode_handlers = {'administration': AdminAPI}
