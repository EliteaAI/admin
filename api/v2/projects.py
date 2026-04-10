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
        owner_ids = flask.request.args.getlist("owner_ids", type=int) or None
        #
        # Resolve owner_ids by searching users when search term is provided
        #
        if search and not owner_ids:
            owner_ids = None
            if search:
                matched = self.module.context.rpc_manager.call.auth_search_users(search=search)
                owner_ids = [u["id"] for u in matched] or None
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
            owner_ids=owner_ids,
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
            owner_id = project.get("owner_id")
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
            all_user_ids = set(project_admin_ids)
            if owner_id:
                all_user_ids.add(owner_id)
            #
            user_infos = auth.list_users(user_ids=all_user_ids)
            user_map = {u["id"]: (u["name"] or str(u["email"])) for u in user_infos}
            #
            owner_name = user_map.get(owner_id, str(owner_id)) if owner_id else ""
            other_admin_names = [
                user_map[uid] for uid in project_admin_ids
                if uid != owner_id and uid in user_map
            ]
            #
            if project.get("suspended"):
                status = "suspended"
            elif project.get("create_success") is True:
                status = "active"
            elif project.get("create_success") is False:
                status = "failed"
            else:
                status = "pending"
            #
            project["project_name"] = project["name"]
            project["status"] = status
            project["owner_name"] = owner_name
            project["admin_names"] = other_admin_names
            project["admin_name"] = owner_name
            project["is_personal"] = is_personal_project
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
