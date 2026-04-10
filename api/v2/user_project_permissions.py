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
from tools import auth, api_tools, db, config as c
from collections import defaultdict
from ...models.users import Role


class AdminAPI(api_tools.APIModeHandler):
    @auth.decorators.check_api({
        "permissions": ["configuration.roles.user_project_permissions.view"],
        "recommended_roles": {
            c.ADMINISTRATION_MODE: {"admin": True, "viewer": False, "editor": False},
            c.DEFAULT_MODE: {"admin": False, "viewer": False, "editor": False},
            "developer": {"admin": False, "viewer": False, "editor": False},
        }})
    def get(self):  # pylint: disable=R0201
        """ Process """
        project_ids = self.module.context.rpc_manager.call.projects_get_personal_project_ids()
        if not project_ids:
            return {'error': "Personal projects not set"}, 400

        project_id = project_ids[0]

        roles = self.module.get_roles(project_id)
        auth_permissions = self.module.get_permissions(project_id)
        all_permissions = auth.local_permissions
        role_map = defaultdict(set)
        for i in auth_permissions:
            role_map[i['name']].add(i['permission'])

        if request.args.get('old_format') is None:
            role_map = dict(role_map)
            for i in role_map.keys():
                role_map[i] = sorted(role_map[i])
            return role_map, 200

        permissions_map = [{
            "name": permission,
            **{
                role["name"]: permission in role_map[role["name"]]
                for role in roles
            }
        } for permission in sorted(all_permissions)]

        return permissions_map, 200

    @auth.decorators.check_api({
        "permissions": ["configuration.roles.user_project_permissions.edit"],
        "recommended_roles": {
            c.ADMINISTRATION_MODE: {"admin": True, "viewer": False, "editor": False},
            c.DEFAULT_MODE: {"admin": False, "viewer": False, "editor": False},
            "developer": {"admin": False, "viewer": False, "editor": False},
        }})
    def put(self):  # pylint: disable=R0201
        """ Process """
        for_team_projects = request.args.get('team_projects') is not None
        create_role_if_not_exist = request.args.get('create_role_if_not_exist') is not None
        append_user_role = request.args.get('append_user_role') is not None

        if isinstance(request.json, list):
            role_map = defaultdict(list)
            for i in request.json:
                role_name = i.pop('name')
                for k, v in i.items():
                    if v:
                        role_map[k].append(role_name)
        elif isinstance(request.json, dict):
            role_map = request.json
        else:
            return {'error': f'Unknown payload type {type(request.json)}'}, 400

        personal_project_ids = self.module.context.rpc_manager.call.projects_get_personal_project_ids()
        if not personal_project_ids:
            return {'error': "Personal projects not set"}, 400
        personal_project_ids = set(personal_project_ids)
        project_ids = personal_project_ids
        if for_team_projects:
            from tools import elitea_config  # pylint: disable=C0415,E0401
            ai_project_id = elitea_config.get("ai_project_id")
            if ai_project_id:
                ai_project_id = int(ai_project_id)
            project_ids = [
                i['id']
                for i in self.module.context.rpc_manager.call.project_list()
                if (i['id'] not in personal_project_ids) and (i['id'] != ai_project_id)
            ]
        log.info(f'changing permissions for projects: {project_ids}')

        for project_id in project_ids:
            with db.get_session(project_id) as session:
                roles = session.query(Role).where(Role.name.in_(role_map.keys())).all()
                if create_role_if_not_exist:
                    roles_not_exist_in_project = set(role_map.keys()) - {r.name for r in roles}
                    if roles_not_exist_in_project:
                        role = self.module.add_role(project_id=project_id, role_names=list(roles_not_exist_in_project))
                    roles = session.query(Role).where(Role.name.in_(role_map.keys())).all()
                for role in roles:
                    role.permissions.delete(synchronize_session='fetch')
                    self.module.set_permissions_for_role(
                        project_id=project_id,
                        role_name=role.name,
                        permissions=role_map[role.name],
                        session=session,
                        commit=False
                    )
                session.commit()
                if append_user_role:
                    project_users = self.module.get_users_roles_in_project(project_id, filter_system_user=True)
                    for user_id, user_roles in project_users.items():
                        if missing_user_roles := set(role_map.keys()) - set(user_roles):
                            user_roles.extend(missing_user_roles)
                            self.module.context.rpc_manager.call.update_roles_for_user(
                                project_id, user_id, user_roles
                            )
        return {'role_map': dict(role_map)}, 200


class API(api_tools.APIBase):  # pylint: disable=R0903
    url_params = api_tools.with_modes([
        '',
    ])

    mode_handlers = {
        c.ADMINISTRATION_MODE: AdminAPI,
    }
