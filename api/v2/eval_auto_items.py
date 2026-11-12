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

""" Scheduled evaluation results: each agent's latest verdict, and one agent's history.

Read-only views over ``elitea_core``'s job items, for the Super Admin dashboard.
"""

import flask  # pylint: disable=E0401

from tools import auth, api_tools, register_openapi  # pylint: disable=E0401

from .eval_platform_dimensions import _VIEW_ROLES

STATUSES = ("passed", "warning", "failed", "not_evaluated")
REASONS = ("HITL_REQUIRED", "OAUTH_REQUIRED", "AGENT_BROKEN", "TIMEOUT", "OWNER_UNAVAILABLE",
           "BUDGET_BLOCKED", "NO_DATASET", "OTHER")
_MAX_LIMIT = 1000
_MAX_HISTORY = 200
_MAX_SEARCH = 200


def _list_args(args):
    """Validated list filters, or an error message."""
    # ``args.get(type=int)`` silently falls back to the default on a bad value; reject it instead.
    numbers = {}
    for name, default in (("project_id", None), ("limit", 50), ("offset", 0)):
        raw = args.get(name)
        if raw in (None, ""):
            numbers[name] = default
            continue
        try:
            numbers[name] = int(raw)
        except ValueError:
            return None, f"{name} must be an integer"
    project_id, limit, offset = numbers["project_id"], numbers["limit"], numbers["offset"]
    if project_id is not None and project_id < 1:
        return None, "project_id must be a positive integer"
    status = args.get("status") or None
    if status is not None and status not in STATUSES:
        return None, f"status must be one of {', '.join(STATUSES)}"
    reason = args.get("reason") or None
    if reason is not None and reason not in REASONS:
        return None, f"reason must be one of {', '.join(REASONS)}"
    search = (args.get("search") or "").strip() or None
    if search is not None and len(search) > _MAX_SEARCH:
        return None, f"search must be at most {_MAX_SEARCH} characters"
    if not 1 <= limit <= _MAX_LIMIT or offset < 0:
        return None, f"limit must be 1..{_MAX_LIMIT} and offset non-negative"
    return {"project_id": project_id, "status": status, "reason": reason, "search": search,
            "limit": limit, "offset": offset}, None


def _history_limit(args):
    """The validated history page size, or an error message."""
    raw = args.get("limit")
    if raw in (None, ""):
        return 20, None
    try:
        limit = int(raw)
    except ValueError:
        return None, "limit must be an integer"
    if not 1 <= limit <= _MAX_HISTORY:
        return None, f"limit must be 1..{_MAX_HISTORY}"
    return limit, None


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=R0903
    """ API """

    @property
    def _rpc(self):
        return self.module.context.rpc_manager.call

    @register_openapi(
        name="List Scheduled Evaluation Results",
        description=(
            "Each agent's latest scheduled evaluation result, or one agent's history when "
            "project_id and application_id are given in the path."
        ),
        parameters=[
            {"name": "project_id", "in": "path", "schema": {"type": "integer"},
             "description": "History mode only; in the list, project_id is a query filter."},
            {"name": "application_id", "in": "path", "schema": {"type": "integer"},
             "description": "History mode only."},
            {"name": "project_id", "in": "query", "schema": {"type": "integer"}},
            {"name": "status", "in": "query", "schema": {"type": "string", "enum": list(STATUSES)}},
            {"name": "reason", "in": "query", "schema": {"type": "string", "enum": list(REASONS)}},
            {"name": "search", "in": "query", "schema": {"type": "string", "maxLength": _MAX_SEARCH},
             "description": "Matches the agent name, or the agent id when it is a number."},
            {"name": "limit", "in": "query", "schema": {"type": "integer"}},
            {"name": "offset", "in": "query", "schema": {"type": "integer"}},
        ],
    )
    @auth.decorators.check_api({
        "permissions": ["configuration.evaluation.auto.view"],
        "recommended_roles": _VIEW_ROLES,
    })
    def get(self, project_id: int = None, application_id: int = None):
        if project_id is not None and application_id is not None:
            limit, error = _history_limit(flask.request.args)
            if error:
                return {"ok": False, "error": error}, 400
            return self._rpc.elitea_core_eval_auto_history(project_id, application_id, limit=limit), 200
        #
        filters, error = _list_args(flask.request.args)
        if error:
            return {"ok": False, "error": error}, 400
        return self._rpc.elitea_core_eval_auto_list(**filters), 200


class API(api_tools.APIBase):  # pylint: disable=R0903
    url_params = [
        "<string:mode>",
        "<string:mode>/<int:project_id>/<int:application_id>",
    ]

    mode_handlers = {
        'administration': AdminAPI,
    }
