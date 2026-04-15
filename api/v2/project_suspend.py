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

""" API """
from flask import request

from pylon.core.tools import log  # pylint: disable=E0611,E0401,W0611

from tools import auth, api_tools, db  # pylint: disable=E0401


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=R0903,C0115
    @auth.decorators.check_api({
        "permissions": ["projects.projects.projects.edit"],
        "recommended_roles": {
            "administration": {"admin": True, "viewer": False, "editor": False},
            "default": {"admin": True, "viewer": False, "editor": False},
            "developer": {"admin": True, "viewer": False, "editor": False},
        }})
    @api_tools.endpoint_metrics
    def put(self, project_id: int, **kwargs):
        """ Toggle project suspended state """
        from plugins.projects.models.project import Project

        suspended = request.json.get("suspended")
        if suspended is None:
            return {"error": "suspended field is required"}, 400
        #
        with db.with_project_schema_session(None) as session:
            project = session.query(Project).where(
                Project.id == project_id,
            ).first()
            if not project:
                return {"error": "Project not found"}, 404
            project.suspended = bool(suspended)
            session.commit()
            return {"id": project.id, "suspended": project.suspended}, 200


class API(api_tools.APIBase):  # pylint: disable=R0903
    url_params = [
        "<string:mode>/<int:project_id>",
    ]

    mode_handlers = {
        'administration': AdminAPI,
    }
