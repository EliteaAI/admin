""" SCIM 2.0 service provider for IdP provisioning (#5202).

Tenant URL for the IdP: ``<deployment>/api/v2/admin/scim/administration``. Requests carry a
``scim1.`` bearer that the auth plugin hands to this plugin's verifier (module.py): such a
request acts as the provisioning service user, and only that user is served here.
"""
import json

import flask
from pylon.core.tools import log  # pylint: disable=E0401
from tools import api_tools, this  # pylint: disable=E0401

from ...utils.scim import protocol
from ...utils.scim.protocol import ScimError

RESOURCES = ("Users", "Groups")


def _reply(body, status=200):
    if body is None:
        return flask.Response(status=status)
    return flask.Response(json.dumps(body), status=status, mimetype=protocol.CONTENT_TYPE)


def _error(error: ScimError):
    return _reply(error.body(), error.status)


def _body():
    body = flask.request.get_json(force=True, silent=True)
    if not isinstance(body, dict):
        raise ScimError(400, "A JSON object is required", "invalidSyntax")
    return body


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=R0903
    def _serve(self, method, resource=None, resource_id=None):
        scim = this.module.scim
        try:
            if scim is None:
                raise ScimError(404, "SCIM provisioning is not enabled")
            if not scim.is_provisioner(getattr(flask.g.auth, "id", None)):
                raise ScimError(401, "A SCIM token is required")
            return self._dispatch(scim.service, method, resource, resource_id)
        except ScimError as exc:
            return _error(exc)
        except Exception:  # pylint: disable=W0703
            log.exception("SCIM %s %s failed", method, resource)
            return _error(ScimError(500, "Internal error"))

    @staticmethod
    def _dispatch(service, method, resource, resource_id):  # pylint: disable=R0911,R0912
        args = flask.request.args
        if resource == "ServiceProviderConfig" and method == "get":
            return _reply(protocol.service_provider_config())
        if resource == "ResourceTypes" and method == "get":
            return _reply(protocol.list_response(protocol.resource_types(service.base_url), 2))
        if resource == "Schemas" and method == "get":
            return _reply(protocol.list_response(protocol.schemas(), 2))
        if resource not in RESOURCES:
            raise ScimError(404, "Unknown resource")
        users = resource == "Users"
        if resource_id is None:
            if method == "get":
                start, count = protocol.page_args(args)
                if users:
                    return _reply(service.list_users(args.get("filter"), start, count))
                return _reply(service.list_groups(args.get("filter"), start, count, args.get("excludedAttributes")))
            if method == "post":
                return _reply((service.create_user if users else service.create_group)(_body()), 201)
            raise ScimError(405, "Method not allowed")
        if method == "get":
            if users:
                return _reply(service.get_user(resource_id))
            return _reply(service.get_group(resource_id, args.get("excludedAttributes")))
        if method == "put":
            return _reply((service.replace_user if users else service.replace_group)(resource_id, _body()))
        if method == "patch":
            if users:
                return _reply(service.patch_user(resource_id, _body()))
            service.patch_group(resource_id, _body())
            return _reply(None, 204)
        if method == "delete":
            (service.delete_user if users else service.delete_group)(resource_id)
            return _reply(None, 204)
        raise ScimError(405, "Method not allowed")

    def get(self, resource=None, resource_id=None, **kwargs):
        return self._serve("get", resource, resource_id)

    def post(self, resource=None, resource_id=None, **kwargs):
        return self._serve("post", resource, resource_id)

    def put(self, resource=None, resource_id=None, **kwargs):
        return self._serve("put", resource, resource_id)

    def patch(self, resource=None, resource_id=None, **kwargs):
        return self._serve("patch", resource, resource_id)

    def delete(self, resource=None, resource_id=None, **kwargs):
        return self._serve("delete", resource, resource_id)


class API(api_tools.APIBase):  # pylint: disable=R0903
    url_params = [
        '<string:mode>',
        '<string:mode>/<string:resource>',
        '<string:mode>/<string:resource>/<string:resource_id>',
    ]
    mode_handlers = {'administration': AdminAPI}
