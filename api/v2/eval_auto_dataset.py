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

""" The probes of the scheduled evaluation's platform health check, and their resync.

Agents with no dataset of their own are run on these probes plus their conversation starters. Each
agent gets its own copy on its first run; a resync rewrites the copies from the current probes.
"""

import flask  # pylint: disable=E0401

from tools import auth, api_tools, register_openapi  # pylint: disable=E0401

from .eval_platform_dimensions import _VIEW_ROLES, _WRITE_ROLES

# The resync walks every project, like Run now.
_RESYNC_TIMEOUT = 300


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=R0903
    """ API """

    @property
    def _rpc(self):
        return self.module.context.rpc_manager.call

    @register_openapi(
        name="Get Scheduled Evaluation Default Dataset",
        description="Return the probes agents without a dataset of their own are evaluated on.",
    )
    @auth.decorators.check_api({
        "permissions": ["configuration.evaluation.auto.view"],
        "recommended_roles": _VIEW_ROLES,
    })
    def get(self):
        return self._rpc.elitea_core_eval_auto_get_platform_dataset(), 200

    @register_openapi(
        name="Update Scheduled Evaluation Default Dataset",
        description=(
            "Replace the probes with the given list. Agents keep their copies until a resync."
        ),
    )
    @auth.decorators.check_api({
        "permissions": ["configuration.evaluation.auto.edit"],
        "recommended_roles": _WRITE_ROLES,
    })
    def put(self):
        body = flask.request.get_json(silent=True)
        if not isinstance(body, dict) or not isinstance(body.get("probes"), list):
            return {"ok": False, "error": "body must be a JSON object with a probes list"}, 400
        result = self._rpc.elitea_core_eval_auto_set_platform_probes(body["probes"])
        return result, 200 if result.get("ok") else 400

    @register_openapi(
        name="Resync Scheduled Evaluation Default Dataset",
        description="Rewrite every agent's copy of the probes from the current list.",
    )
    @auth.decorators.check_api({
        "permissions": ["configuration.evaluation.auto.edit"],
        "recommended_roles": _WRITE_ROLES,
    })
    def post(self):
        result = self.module.context.rpc_manager.timeout(_RESYNC_TIMEOUT).elitea_core_eval_auto_resync_platform_dataset()
        # Refused when the registry has no active probes, which would empty every copy.
        return result, 200 if result.get("ok") else 409


class API(api_tools.APIBase):  # pylint: disable=R0903
    url_params = [
        "<string:mode>",
    ]

    mode_handlers = {
        'administration': AdminAPI,
    }
