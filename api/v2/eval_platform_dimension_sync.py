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

""" Push a platform eval dimension's current definition to the projects using it (§16.1).

A separate module from the CRUD API because ``APIBase`` maps one handler method per HTTP verb,
and there ``post`` is already the create verb.

Update-only: a project that never attached the dimension is left alone rather than having a
copy conjured into it.
"""

from tools import auth, api_tools, register_openapi  # pylint: disable=E0401

from .eval_platform_dimensions import _WRITE_ROLES, _call

# Matches the bulk resync task's own budget (`tasks/eval_tasks.py`).
_RESYNC_TIMEOUT = 600


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=R0903
    """ API """

    @property
    def _rpc(self):
        # The resync walks project schemas one at a time, so it needs the same headroom the bulk
        # task gives itself (`tasks/eval_tasks.py`) — on the default timeout this returns a failure
        # to the admin while the per-project commits are in fact still landing.
        return self.module.context.rpc_manager.timeout(_RESYNC_TIMEOUT)

    @register_openapi(
        name="Sync Platform Eval Dimension To Projects",
        description=(
            "Push the dimension's current definition into every project that already holds a "
            "copy. Projects that never attached it are untouched."
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
    def post(self, dimension_uuid: str):
        result, error = _call(
            self._rpc.elitea_core_platform_dimension_resync_one, dimension_uuid,
        )
        return error or (result, 200)


class API(api_tools.APIBase):  # pylint: disable=R0903
    url_params = [
        "<string:mode>/<string:dimension_uuid>",
    ]

    mode_handlers = {
        'administration': AdminAPI,
    }
