#!/usr/bin/python3
# coding=utf-8

#   Copyright 2026 EPAM Systems
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

""" Platform-wide evaluation dimensions (§16.1).

The catalog of platform-tier eval dimensions that every project can reuse. The registry lives
in ``elitea_core``; this API is a thin authenticated shell over its RPCs.

Writes touch the registry only. A project gets its own copy when it attaches the dimension,
and a later definition edit reaches those projects through the sync endpoint.

Deactivate rather than delete: project bindings FK to the projected rows with ON DELETE
CASCADE.
"""

import flask  # pylint: disable=E0401

from pylon.core.tools import log  # pylint: disable=E0611,E0401,W0611

from tools import auth, api_tools, register_openapi  # pylint: disable=E0401

_VIEW_ROLES = {
    "administration": {"super_admin": True, "admin": True, "viewer": True, "editor": True},
    "default": {"super_admin": True, "admin": True, "viewer": True, "editor": True},
    "developer": {"super_admin": True, "admin": True, "viewer": True, "editor": True},
}
_WRITE_ROLES = {
    "administration": {"super_admin": True, "admin": True, "viewer": False, "editor": True},
    "default": {"super_admin": True, "admin": True, "viewer": False, "editor": True},
    "developer": {"super_admin": True, "admin": True, "viewer": False, "editor": True},
}


def _call(rpc_func, *args, **kwargs):
    """Invoke a registry RPC, mapping its domain errors onto their intended HTTP status.

    ``elitea_core``'s eval errors carry ``http_status``; the RPC runs in-process so the
    original exception object reaches us intact.
    """
    try:
        return rpc_func(*args, **kwargs), None
    except Exception as exc:  # pylint: disable=broad-except
        status = getattr(exc, "http_status", None)
        if status is None:
            raise
        return None, ({"ok": False, "error": str(exc)}, status)


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=R0903
    """ API """

    @property
    def _rpc(self):
        return self.module.context.rpc_manager.call

    @register_openapi(
        name="List Platform Eval Dimensions",
        description="List the platform-wide evaluation dimension catalog.",
        parameters=[
            {"name": "dimension_uuid", "in": "path", "required": False,
             "schema": {"type": "string"},
             "description": "Registry uuid. Omit to list the whole catalog."},
            {"name": "active_only", "in": "query", "schema": {"type": "boolean"},
             "description": "Return only active dimensions."},
        ],
    )
    @auth.decorators.check_api({
        "permissions": ["configuration.evaluation.platform_dimensions.view"],
        "recommended_roles": _VIEW_ROLES,
    })
    def get(self, dimension_uuid: str = None):
        if dimension_uuid is not None:
            dimension = self._rpc.elitea_core_platform_dimension_get(dimension_uuid)
            if dimension is None:
                return {"ok": False, "error": "not found"}, 404
            return dimension, 200
        #
        active_only = flask.request.args.get("active_only", "").lower() in ("1", "true")
        rows = self._rpc.elitea_core_platform_dimension_list(active_only=active_only)
        return {"total": len(rows), "rows": rows}, 200

    @register_openapi(
        name="Create Platform Eval Dimension",
        description="Create a platform-wide evaluation dimension and project it into every project.",
    )
    @auth.decorators.check_api({
        "permissions": ["configuration.evaluation.platform_dimensions.create"],
        "recommended_roles": _WRITE_ROLES,
    })
    def post(self):
        try:
            owner_id = flask.g.auth.id
        except Exception:  # pylint: disable=W0703
            owner_id = None
        result, error = _call(
            self._rpc.elitea_core_platform_dimension_create,
            flask.request.json or {}, owner_id=owner_id,
        )
        return error or (result, 201)

    @register_openapi(
        name="Update Platform Eval Dimension",
        description=(
            "Update a platform-wide evaluation dimension and re-project it. "
            "Send is_active to activate or deactivate."
        ),
        parameters=[
            {"name": "dimension_uuid", "in": "path", "schema": {"type": "string"},
             "description": "Registry uuid."},
        ],
    )
    @auth.decorators.check_api({
        "permissions": ["configuration.evaluation.platform_dimensions.edit"],
        "recommended_roles": _WRITE_ROLES,
    })
    def put(self, dimension_uuid: str):
        result, error = _call(
            self._rpc.elitea_core_platform_dimension_update,
            dimension_uuid, flask.request.json or {},
        )
        return error or (result, 200)

    @register_openapi(
        name="Deactivate Platform Eval Dimension",
        description=(
            "Deactivate a platform-wide evaluation dimension. Soft only — existing project "
            "bindings and run history are preserved."
        ),
        parameters=[
            {"name": "dimension_uuid", "in": "path", "schema": {"type": "string"},
             "description": "Registry uuid."},
        ],
    )
    @auth.decorators.check_api({
        "permissions": ["configuration.evaluation.platform_dimensions.delete"],
        "recommended_roles": _WRITE_ROLES,
    })
    def delete(self, dimension_uuid: str):
        result, error = _call(
            self._rpc.elitea_core_platform_dimension_set_active,
            dimension_uuid, is_active=False,
        )
        return error or (result, 200)


class API(api_tools.APIBase):  # pylint: disable=R0903
    url_params = [
        "<string:mode>",
        "<string:mode>/<string:dimension_uuid>",
    ]

    mode_handlers = {
        'administration': AdminAPI,
    }
