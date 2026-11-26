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

""" The projects whose admins let the scheduled evaluation score agents from their chat history.

Names and ids only: the Super Admin sees who opted in, never the chats.
"""

from tools import auth, api_tools, register_openapi  # pylint: disable=E0401

from .eval_auto import _AUTO_VIEW_ROLES, _rpc_result

# The listing walks every project, like Run now.
_LIST_TIMEOUT = 120


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=R0903
    """ API """

    @register_openapi(
        name="List Scheduled Evaluation History Consents",
        description=(
            "The projects that allow evaluation from chat history, and whether each is in the "
            "evaluation's project scope."
        ),
    )
    @auth.decorators.check_api({
        "permissions": ["configuration.evaluation.auto.view"],
        "recommended_roles": _AUTO_VIEW_ROLES,
    })
    def get(self):
        result, error = _rpc_result(
            self.module.context.rpc_manager.timeout(_LIST_TIMEOUT).elitea_core_eval_auto_history_consents,
        )
        return error or (result, 200)


class API(api_tools.APIBase):  # pylint: disable=R0903
    url_params = [
        "<string:mode>",
    ]

    mode_handlers = {
        'administration': AdminAPI,
    }
