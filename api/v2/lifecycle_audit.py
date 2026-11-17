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

""" API: project and user lifecycle audit (#7504) - read and CSV export only """

import datetime

import flask  # pylint: disable=E0401

from tools import auth, api_tools, register_openapi  # pylint: disable=E0401

from ...utils.lifecycle_audit import query

PERMISSION = "models.admin.lifecycle_audit.view"
RECOMMENDED_ROLES = {
    "administration": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
}

PARAMETERS = [
    {"name": "tab", "in": "query", "schema": {"type": "string", "enum": list(query.TABS)}},
    {"name": "date_from", "in": "query", "schema": {"type": "string", "format": "date-time"},
     "description": "Required unless all_time is set."},
    {"name": "date_to", "in": "query", "schema": {"type": "string", "format": "date-time"}},
    {"name": "all_time", "in": "query", "schema": {"type": "boolean"}},
    {"name": "event_type", "in": "query", "schema": {"type": "string"}, "description": "Comma separated."},
    {"name": "project_id", "in": "query", "schema": {"type": "integer"}},
    {"name": "project_name", "in": "query", "schema": {"type": "string"}},
    {"name": "project_type", "in": "query", "schema": {"type": "string", "enum": ["team", "private"]}},
    {"name": "user_id", "in": "query", "schema": {"type": "integer"}},
    {"name": "user_name", "in": "query", "schema": {"type": "string"}},
    {"name": "user_email", "in": "query", "schema": {"type": "string"}},
    {"name": "actor", "in": "query", "schema": {"type": "string"}, "description": "Actor name, email or id."},
    {"name": "role", "in": "query", "schema": {"type": "string"}},
    {"name": "admin_access", "in": "query", "schema": {"type": "string", "enum": list(query.ADMIN_ACCESS)}},
    {"name": "result", "in": "query", "schema": {"type": "string"}},
    {"name": "source", "in": "query", "schema": {"type": "string"}},
    {"name": "q", "in": "query", "schema": {"type": "string"}},
    {"name": "sort_by", "in": "query", "schema": {"type": "string", "enum": sorted(query.SORT_COLUMNS)}},
    {"name": "sort_order", "in": "query", "schema": {"type": "string", "enum": ["asc", "desc"]}},
    {"name": "limit", "in": "query", "schema": {"type": "integer", "maximum": query.MAX_LIMIT}},
    {"name": "offset", "in": "query", "schema": {"type": "integer"}},
]


def _params():
    params = flask.request.args.to_dict()
    event_types = flask.request.args.getlist("event_type") + flask.request.args.getlist("event_type[]")
    if event_types:
        params["event_type"] = ",".join(event_types)
    return query.parse(params)


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=R0903
    """ Lifecycle audit events """

    @register_openapi(
        name="List Lifecycle Audit Events",
        description="Project and user lifecycle and access-change events, filtered, sorted and paginated.",
        parameters=PARAMETERS,
    )
    @auth.decorators.check_api({"permissions": [PERMISSION], "recommended_roles": RECOMMENDED_ROLES})
    @api_tools.endpoint_metrics
    def get(self, **kwargs):
        """ One page of events """
        _ = kwargs
        try:
            params = _params()
        except ValueError as error:
            return {"error": str(error)}, 400
        return self.module.lifecycle_audit_query(params), 200


class AdminExportAPI(api_tools.APIModeHandler):  # pylint: disable=R0903
    """ Lifecycle audit CSV export """

    @register_openapi(
        name="Export Lifecycle Audit Events",
        description="Every event matching the filters, in the requested order, as CSV with UTC timestamps.",
        parameters=[item for item in PARAMETERS if item["name"] not in ("limit", "offset")],
    )
    @auth.decorators.check_api({"permissions": [PERMISSION], "recommended_roles": RECOMMENDED_ROLES})
    def get(self, **kwargs):
        """ Streamed CSV """
        _ = kwargs
        try:
            params = _params()
        except ValueError as error:
            return {"error": str(error)}, 400
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        filename = f"lifecycle_audit_{params.get('tab') or 'all'}_{stamp}.csv"
        stream = self.module.lifecycle_audit_export(params)
        return flask.Response(
            flask.stream_with_context(stream),
            mimetype="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-Content-Type-Options": "nosniff",
                "Cache-Control": "no-store",
            },
        )


class API(api_tools.APIBase):  # pylint: disable=R0903
    """ GET only: audit records are never changed through the API (AC-19) """

    url_params = [
        "<string:mode>",
        "<string:mode>/<string:export>",
    ]

    mode_handlers = {
        "administration": AdminAPI,
    }

    def get(self, mode, export=None, **kwargs):  # pylint: disable=W0221
        """ /administration lists, /administration/export downloads """
        if export is None:
            return super().get(mode=mode, **kwargs)
        if export != "export" or mode != "administration":
            return {"error": "not found"}, 404
        return AdminExportAPI(self, mode).get(**kwargs)
