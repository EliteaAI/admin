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

""" Slot """

from pylon.core.tools import log  # pylint: disable=E0611,E0401
from pylon.core.tools import web  # pylint: disable=E0611,E0401

from tools import auth  # pylint: disable=E0401
from tools import theme  # pylint: disable=E0401


class Slot:  # pylint: disable=E1101,R0903
    """
        Slot Resource

        self is pointing to current Module instance

        web.slot decorator takes one argument: slot name
        Note: web.slot decorator must be the last decorator (at top)

        Slot resources use check_slot auth decorator
        auth.decorators.check_slot takes the following arguments:
        - permissions
        - scope_id=1
        - access_denied_reply=None -> can be set to content to return in case of 'access denied'

    """

    @web.slot("admin_mode_projects_edit_content")
    @auth.decorators.check_slot(["projects.projects"], access_denied_reply=theme.access_denied_part)
    def _project_edit_content(self, context, slot, payload):
        _ = slot
        #
        try:
            project = int(payload.request.args.get("project"))
        except:  # pylint: disable=W0702
            return theme.access_denied_part
        #
        project_ids = [item["id"] for item in self.context.rpc_manager.call.project_list()]
        if project not in project_ids:
            return theme.access_denied_part
        #
        # from tools import project_constants as pc
        # template = pc['PROJECT_SCHEMA_TEMPLATE']
        # # project_scope_name = f"Project-{project}"
        # project_scope_name = template.format(project)
        # scope_map = {item["name"]: item["id"] for item in auth.list_scopes()}
        # #
        # if project_scope_name not in scope_map:
        #     return theme.access_denied_part
        #
        with context.app.app_context():
            return self.descriptor.render_template(
                "project_edit/content.html",
                project=project,
            )

    @web.slot("admin_mode_projects_edit_scripts")
    @auth.decorators.check_slot(["projects.projects"])
    def _project_edit_scripts(self, context, slot, payload):
        _ = slot
        #
        try:
            project = int(payload.request.args.get("project"))
        except:  # pylint: disable=W0702
            return
        #
        project_ids = [item["id"] for item in self.context.rpc_manager.call.project_list()]
        if project not in project_ids:
            return
        #
        with context.app.app_context():
            return self.descriptor.render_template(
                "project_edit/scripts.html",
                project=project,
            )
