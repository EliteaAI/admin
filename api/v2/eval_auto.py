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

""" Environment-wide scheduled agent evaluation: its settings and the "Run now" trigger.

The job, its settings and its results live in ``elitea_core``; this API is a thin authenticated
shell over its RPCs. Settings are merged and clamped there, so a partial body is fine.
"""

import flask  # pylint: disable=E0401

from tools import auth, api_tools, register_openapi  # pylint: disable=E0401

from .eval_platform_dimensions import _VIEW_ROLES, _WRITE_ROLES

# Run now enumerates every project before it returns; the tick allows itself 120 s for the
# project list alone.
_RUN_NOW_TIMEOUT = 300


def _user_id():
    try:
        return flask.g.auth.id
    except Exception:  # pylint: disable=W0703
        return None


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=R0903
    """ API """

    @property
    def _rpc(self):
        return self.module.context.rpc_manager.call

    @register_openapi(
        name="Get Scheduled Evaluation Settings",
        description="Return the effective settings of the environment-wide scheduled evaluation.",
    )
    @auth.decorators.check_api({
        "permissions": ["configuration.evaluation.auto.view"],
        "recommended_roles": _VIEW_ROLES,
    })
    def get(self):
        return self._rpc.elitea_core_eval_auto_get_config(), 200

    @register_openapi(
        name="Update Scheduled Evaluation Settings",
        description=(
            "Merge the given keys into the scheduled evaluation settings. Out-of-range values are "
            "clamped and unknown keys dropped; the effective settings are returned."
        ),
    )
    @auth.decorators.check_api({
        "permissions": ["configuration.evaluation.auto.edit"],
        "recommended_roles": _WRITE_ROLES,
    })
    def put(self):
        settings = flask.request.get_json(silent=True)
        if not isinstance(settings, dict):
            return {"ok": False, "error": "body must be a JSON object"}, 400
        result = self._rpc.elitea_core_eval_auto_set_config(settings, user_id=_user_id())
        if not result.get("ok"):
            return result, 400
        return result["settings"], 200

    @register_openapi(
        name="Run Scheduled Evaluation Now",
        description=(
            "Start a job now, even with the schedule off or outside the launch window. Returns the job id, "
            "or why none started (e.g. a job is already running)."
        ),
    )
    @auth.decorators.check_api({
        "permissions": ["configuration.evaluation.auto.run"],
        "recommended_roles": _WRITE_ROLES,
    })
    def post(self):
        result = self.module.context.rpc_manager.timeout(_RUN_NOW_TIMEOUT).elitea_core_eval_auto_run_now(
            user_id=_user_id(),
        )
        return result, 200 if result.get("started") else 409


class API(api_tools.APIBase):  # pylint: disable=R0903
    url_params = [
        "<string:mode>",
    ]

    mode_handlers = {
        'administration': AdminAPI,
    }
