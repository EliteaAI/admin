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
import flask  # pylint: disable=E0401

from pylon.core.tools import log  # pylint: disable=E0611,E0401,W0611

from tools import auth, api_tools  # pylint: disable=E0401


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=R0903,C0115
    @auth.decorators.check_api({
        "permissions": ["projects.projects.projects.view"],
        "recommended_roles": {
            "administration": {"admin": True, "viewer": False, "editor": False},
            "default": {"admin": True, "viewer": True, "editor": False},
            "developer": {"admin": True, "viewer": False, "editor": False},
        }})
    def get(self):
        """ Process """
        limit = flask.request.args.get("limit", 20, type=int)
        offset = flask.request.args.get("offset", 0, type=int)
        search = flask.request.args.get("search", None, type=str)
        sort_by = flask.request.args.get("sort_by", "name", type=str)
        sort_order = flask.request.args.get("sort_order", "asc", type=str)
        project_type = flask.request.args.get("project_type", None, type=str)
        #
        # DB-level pagination, filtering, sorting
        #
        data = self.module.context.rpc_manager.call.project_list_paginated(
            limit=limit,
            offset=offset,
            search=search or None,
            sort_by=sort_by,
            sort_order=sort_order,
            project_type=project_type or None,
        )
        #
        rows = data["rows"]
        #
        # Enrich only the current page with admin names
        #
        for project in rows:
            project_users = self.module.get_users_roles_in_project(
                project["id"],
                filter_system_user=True,
            )
            #
            is_personal_project = project["name"].startswith("project_user_")
            project_admin_ids = []
            #
            if is_personal_project:
                project_admin_ids.extend(
                    user_id for user_id, user_roles in project_users.items()
                    if "editor" in user_roles
                )
            #
            project_admin_ids.extend(
                user_id for user_id, user_roles in project_users.items()
                if "admin" in user_roles
            )
            #
            user_infos = auth.list_users(user_ids=set(project_admin_ids))
            #
            admin_names = []
            for user in user_infos:
                if user["name"] is not None:
                    admin_names.append(user["name"])
                else:
                    admin_names.append(str(user["email"]))
            #
            project["project_name"] = project["name"]
            project["admin_name"] = ", ".join(admin_names)
            project["is_personal"] = is_personal_project
            #
            # Derive unified status from create_success + suspended
            #
            if project.get("suspended"):
                project["status"] = "suspended"
            elif project.get("create_success") is True:
                project["status"] = "active"
            elif project.get("create_success") is False:
                project["status"] = "failed"
            else:
                project["status"] = "pending"
        #
        return {
            "total": data["total"],
            "rows": rows,
            "counts": data["counts"],
        }


class API(api_tools.APIBase):  # pylint: disable=R0903
    url_params = [
        "<string:mode>",
    ]

    mode_handlers = {
        'administration': AdminAPI,
    }
