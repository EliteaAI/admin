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

import flask  # pylint: disable=E0401,W0611

from pylon.core.tools import log  # pylint: disable=E0611,E0401,W0611

from tools import auth  # pylint: disable=E0401
from tools import api_tools  # pylint: disable=E0401


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=R0903
    """ API """

    @auth.decorators.check_api(["migration.permissions"])
    def post(self):  # pylint: disable=R0912,R0914,R0915
        """ Process POST """
        data = flask.request.get_json()
        mode = data.get("mode", "unknown")
        #
        logs = []
        #
        if mode in [
                "add_user_project_defaults",
                "add_team_project_defaults",
                "add_public_project_defaults",
        ]:
            #
            # Build default role map
            #
            default_project_roles = auth.get_roles(mode="default")
            default_project_permissions = auth.get_permissions(mode="default")
            #
            default_role_map = {}
            #
            for item in default_project_roles:
                default_role_map[item["name"]] = set()
            #
            for item in default_project_permissions:
                default_role_map[item["name"]].add(item["permission"])
            #
            for item in default_project_roles:
                default_role_map[item["name"]] = list(default_role_map[item["name"]])
                default_role_map[item["name"]].sort()
            #
            log.debug("Default role map: %s", default_role_map)
            #
            # Get projects
            #
            personal_project_ids = \
                self.module.context.rpc_manager.call.projects_get_personal_project_ids()
            #
            if not personal_project_ids:
                return {"error": "Personal projects not set"}, 400
            #
            if mode == "add_user_project_defaults":
                project_ids = personal_project_ids
            elif mode == "add_team_project_defaults":
                from tools import elitea_config  # pylint: disable=E0401,C0415
                #
                ai_project_id = elitea_config.get("ai_project_id")
                #
                if ai_project_id:
                    ai_project_id = int(ai_project_id)
                #
                project_ids = [
                    i['id']
                    for i in self.module.context.rpc_manager.call.project_list()
                    if (i['id'] not in personal_project_ids) and (i['id'] != ai_project_id)
                ]
            elif mode == "add_public_project_defaults":
                from tools import elitea_config  # pylint: disable=E0401,C0415
                #
                ai_project_id = elitea_config.get("ai_project_id")
                #
                if ai_project_id:
                    ai_project_id = int(ai_project_id)
                #
                project_ids = [ai_project_id]
            else:
                project_ids = []
            #
            log.debug("Project IDs: %s", project_ids)
            #
            for project_id in project_ids:
                #
                # Build project role map
                #
                project_roles = self.module.get_roles(project_id)
                project_permissions = self.module.get_permissions(project_id)
                #
                project_role_map = {}
                #
                for item in project_roles:
                    project_role_map[item["name"]] = set()
                #
                for item in project_permissions:
                    project_role_map[item["name"]].add(item["permission"])
                #
                for item in project_roles:
                    project_role_map[item["name"]] = list(project_role_map[item["name"]])
                    project_role_map[item["name"]].sort()
                #
                log.debug("Project role map: %s", project_role_map)
                #
                # Diff
                #
                missing_roles = []
                missing_permissions = []
                #
                for role, permissions in default_role_map.items():
                    if role not in project_role_map:
                        missing_roles.append(role)
                    #
                    role_permissions = project_role_map.get(role, [])
                    #
                    for permission in permissions:
                        if permission not in role_permissions:
                            missing_permissions.append({"role": role, "permission": permission})
                #
                log.debug(f"Project {project_id}: {missing_roles=} {missing_permissions=}")
                logs.append(f"Project {project_id}: {missing_roles=} {missing_permissions=}")
                #
                # Apply
                #
                if missing_roles:
                    try:
                        self.module.context.rpc_manager.call.admin_add_role(
                            project_id, missing_roles
                        )
                    except:  # pylint: disable=W0702
                        log.exception("Failed to add missing roles")
                        logs.append("> Failed to add missing roles")
                #
                for permission in missing_permissions:
                    try:
                        self.module.context.rpc_manager.call.admin_set_permission_for_role(
                            project_id, permission["role"], permission["permission"]
                        )
                    except:  # pylint: disable=W0702
                        log.exception(
                            "Failed to add missing permission: %s:%s",
                            permission["role"], permission["permission"],
                        )
                        #
                        l_role = permission["role"]
                        l_perm = permission["permission"]
                        #
                        logs.append(
                            f"> Failed to add missing permission: {l_role}:{l_perm}"
                        )
        elif mode in [  # pylint: disable=R1702
                "add_user_project_permissions",
                "add_team_project_permissions",
                "add_public_project_permissions",
                "delete_user_project_permissions",
                "delete_team_project_permissions",
                "delete_public_project_permissions",
        ]:
            #
            # Parse input permissions
            #
            permission_items = data.get("permissions", "").strip()
            #
            input_permissions = []
            #
            for item in permission_items.splitlines():
                permission, roles = item.split(":", 1)
                roles = roles.split(",")
                #
                input_permissions.append(
                    (permission, roles)
                )
            #
            # Get projects
            #
            personal_project_ids = \
                self.module.context.rpc_manager.call.projects_get_personal_project_ids()
            #
            if not personal_project_ids:
                return {"error": "Personal projects not set"}, 400
            #
            if mode in ["add_user_project_permissions", "delete_user_project_permissions"]:
                project_ids = personal_project_ids
            elif mode in ["add_team_project_permissions", "delete_team_project_permissions"]:
                from tools import elitea_config  # pylint: disable=E0401,C0415
                #
                ai_project_id = elitea_config.get("ai_project_id")
                #
                if ai_project_id:
                    ai_project_id = int(ai_project_id)
                #
                project_ids = [
                    i['id']
                    for i in self.module.context.rpc_manager.call.project_list()
                    if (i['id'] not in personal_project_ids) and (i['id'] != ai_project_id)
                ]
            elif mode in ["add_public_project_permissions", "delete_public_project_permissions"]:
                from tools import elitea_config  # pylint: disable=E0401,C0415
                #
                ai_project_id = elitea_config.get("ai_project_id")
                #
                if ai_project_id:
                    ai_project_id = int(ai_project_id)
                #
                project_ids = [ai_project_id]
            else:
                project_ids = []
            #
            for project_id in project_ids:
                #
                # Build project role map
                #
                project_roles = self.module.get_roles(project_id)
                project_permissions = self.module.get_permissions(project_id)
                #
                project_role_map = {}
                #
                for item in project_roles:
                    project_role_map[item["name"]] = set()
                #
                for item in project_permissions:
                    project_role_map[item["name"]].add(item["permission"])
                #
                for item in project_roles:
                    project_role_map[item["name"]] = list(project_role_map[item["name"]])
                    project_role_map[item["name"]].sort()
                #
                # Perform
                #
                if mode in [
                        "add_user_project_permissions",
                        "add_team_project_permissions",
                        "add_public_project_permissions",
                ]:
                    #
                    # Diff
                    #
                    missing_roles = []
                    missing_permissions = []
                    #
                    for permission, roles in input_permissions:
                        for role in roles:
                            if role not in project_role_map:
                                missing_roles.append(role)
                            #
                            role_permissions = project_role_map.get(role, [])
                            #
                            if permission not in role_permissions:
                                missing_permissions.append({"role": role, "permission": permission})
                    #
                    logs.append(f"Project {project_id}: {missing_roles=} {missing_permissions=}")
                    #
                    # Apply
                    #
                    if missing_roles:
                        self.module.context.rpc_manager.call.admin_add_role(
                            project_id, missing_roles
                        )
                    #
                    for permission in missing_permissions:
                        self.module.context.rpc_manager.call.admin_set_permission_for_role(
                            project_id, permission["role"], permission["permission"]
                        )
                elif mode in [
                        "delete_user_project_permissions",
                        "delete_team_project_permissions",
                        "delete_public_project_permissions",
                ]:
                    #
                    # Data
                    #
                    removed_permissions = []
                    #
                    # Apply
                    #
                    for permission, roles in input_permissions:
                        for role in roles:
                            if role not in project_role_map:
                                continue
                            #
                            role_permissions = project_role_map.get(role, [])
                            #
                            if permission in role_permissions:
                                self.module.context.rpc_manager.call.admin_remove_permission_from_role(  # pylint: disable=C0301
                                    project_id, role, permission
                                )
                                removed_permissions.append(f"{role}:{permission}")
                    #
                    # Log
                    #
                    logs.append(f"Project {project_id}: {removed_permissions=}")
        #
        else:
            logs.append(f"Current mode: {mode}")
        #
        return {
            "ok": True,
            "logs": "\n".join(logs),
        }


class API(api_tools.APIBase):  # pylint: disable=R0903
    """ API """

    url_params = [
        "<string:mode>",
    ]

    mode_handlers = {
        'administration': AdminAPI,
    }
