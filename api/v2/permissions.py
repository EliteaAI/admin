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
from itertools import groupby

import flask  # pylint: disable=E0401,W0611
import flask_restful  # pylint: disable=E0401
from flask import g, request

from pylon.core.tools import log  # pylint: disable=E0611,E0401,W0611

from tools import auth, api_tools  # pylint: disable=E0401


def group_roles_by_permissions(auth_permissions, roles):
    auth_permissions = sorted(auth_permissions, key=lambda x: x['name'])
    roles_to_permissions = {role["name"]: set() for role in roles}
    for key, group_items in groupby(auth_permissions, key=lambda x: x['name']):
        if key not in roles_to_permissions:
            continue
        for item in group_items:
            roles_to_permissions[key].add(item['permission'])
    return roles_to_permissions

def filter_permissions(permissions: list[str], mode: str) -> list[str]:
    """ Differentiate permissions based on their target mode """
    admin_only_prefixes = (
        'admin.auth',
        'configuration.roles',
        'configuration.users',
        'configuration.advanced',
        'configuration.service_descriptors',
        'configuration.litellm',
        'provider_hub.',
        'modes.',
        'runtime.',
        'migration.',
        'invites.',
        'models.admin.',
        'configuration.roles.permissions',
    )
    
    project_only_prefixes = (
        'models.chat.',
        'models.applications.',
        'models.prompts.',
        'models.social.',
        'models.promptlib_shared.',
        'projects.projects.',
        'social.',
        'notifications.',
    )
    
    filtered = []
    for p in permissions:
        if mode == 'administration':
            # Hide project-level specific features from the administration matrix
            if not p.startswith(project_only_prefixes):
                filtered.append(p)
        else:
            # For 'default' or project specific matrices, hide platform administration features
            if not p.startswith(admin_only_prefixes):
                filtered.append(p)
                
    return filtered


class AdminAPI(api_tools.APIModeHandler):
    @auth.decorators.check_api({
        "permissions": ["configuration.roles.permissions.view"],
        "recommended_roles": {
            "administration": {"admin": True, "viewer": False, "editor": False},
            "default": {"admin": True, "viewer": False, "editor": False},
            "developer": {"admin": True, "viewer": False, "editor": False},
        }})
    def get(self, target_mode):  # pylint: disable=R0201
        """ Process """
        roles = auth.get_roles(target_mode)
        auth_permissions = auth.get_permissions(target_mode)
        log.info(f"{roles=} {auth_permissions=}")
        
        all_permissions = list(auth.local_permissions)
        all_permissions = filter_permissions(all_permissions, target_mode)
        
        # log.info(f"{permissions=} {local_permissions=} {all_permissions=}")
        roles_to_permissions = group_roles_by_permissions(auth_permissions, roles)
        log.info(
            f"{roles=} \n {auth_permissions=} \n {all_permissions=} \n {roles_to_permissions=}")
        all_permissions = sorted(all_permissions)
        return {
            "total": len(all_permissions),
            "rows": [{
                "name": permission,
                **{role["name"]: permission in roles_to_permissions[role["name"]] for
                   role in roles}
            } for permission in all_permissions]
        }

    @auth.decorators.check_api({
        "permissions": ["configuration.roles.permissions.edit"],
        "recommended_roles": {
            "administration": {"admin": True, "viewer": False, "editor": False},
            "default": {"admin": True, "viewer": False, "editor": False},
            "developer": {"admin": True, "viewer": False, "editor": False},
        }})
    def put(self, target_mode):  # pylint: disable=R0201
        """ Process """
        new_data = request.get_json()
        old_data = self.get(target_mode)["rows"]
        old_permissions = set(
            (r, p['name']) for p in old_data for r, v in p.items() if v)
        new_permissions = set(
            (r, p['name']) for p in new_data for r, v in p.items() if v)
        permissions_to_delete = old_permissions - new_permissions
        permissions_to_add = new_permissions - old_permissions
        for permission in permissions_to_add:
            auth.set_permission_for_role(*permission, mode=target_mode)
        for permission in permissions_to_delete:
            auth.remove_permission_from_role(*permission, mode=target_mode)
        return {"ok": True}

    @auth.decorators.check_api({
        "permissions": ["configuration.roles.permissions.edit"],
        "recommended_roles": {
            "administration": {"admin": True, "viewer": False, "editor": False},
            "default": {"admin": True, "viewer": False, "editor": False},
            "developer": {"admin": True, "viewer": False, "editor": False},
        }})
    def post(self, target_mode):
        """ Sync standard permissions to existing shared projects """
        from collections import defaultdict

        if target_mode != "default":
            return {"error": "Sync is only supported for default mode"}, 400

        public_project_id = PublicProjectAPI._get_public_project_id()
        all_projects = self.module.context.rpc_manager.call.project_list()

        central = auth.get_permissions(mode='default')
        role_to_perms = defaultdict(set)
        for p in central:
            role_to_perms[p['name']].add(p['permission'])

        for p in all_projects:
            project_id = p['id']
            project_name = p['name']

            # Skip private and public projects
            if project_name.startswith('project_user_') or project_id == public_project_id:
                continue

            roles = auth.list_project_roles(project_id)
            role_name_to_id = {r['name']: r['id'] for r in roles}

            # Clear existing overrides
            existing = auth.list_project_role_permissions(project_id)
            for entry in existing:
                auth.delete_project_role_permission(project_id, entry['role_id'], entry['permission'])

            # Apply new permissions
            for role_name, perms in role_to_perms.items():
                if role_name not in role_name_to_id:
                    role_id = auth.add_project_role(project_id, role_name)
                    role_name_to_id[role_name] = role_id
                else:
                    role_id = role_name_to_id[role_name]

                for perm in perms:
                    auth.add_project_role_permission(project_id, role_id, perm)

        return {"ok": True, "message": "Successfully synced permissions to shared projects"}


class ProjectAPI(api_tools.APIModeHandler):
    @auth.decorators.check_api({
        "permissions": ["configuration.roles.permissions.view"],
        "recommended_roles": {
            "administration": {"admin": True, "viewer": False, "editor": False},
            "default": {"admin": True, "viewer": False, "editor": False},
            "developer": {"admin": True, "viewer": False, "editor": False},
        }})
    def get(self, project_id):  # pylint: disable=R0201
        """ Process """
        roles = self.module.get_roles(project_id)
        auth_permissions = self.module.get_permissions(project_id)
        
        all_permissions = list(auth.local_permissions)
        all_permissions = filter_permissions(all_permissions, 'default')

        roles_to_permissions = group_roles_by_permissions(auth_permissions, roles)
        all_permissions = sorted(all_permissions)
        return {
            "total": len(all_permissions),
            "rows": [{
                "name": permission,
                **{role["name"]: permission in roles_to_permissions[role["name"]] for
                   role in roles}
            } for permission in all_permissions]
        }

    @auth.decorators.check_api({
        "permissions": ["configuration.roles.permissions.edit"],
        "recommended_roles": {
            "administration": {"admin": True, "viewer": False, "editor": False},
            "default": {"admin": True, "viewer": False, "editor": False},
            "developer": {"admin": True, "viewer": False, "editor": False},
        }})
    def put(self, project_id):  # pylint: disable=R0201
        """ Process """
        new_data = request.get_json()
        old_data = self.get(project_id=project_id)["rows"]
        old_permissions = set(
            (r, p['name']) for p in old_data for r, v in p.items() if v)
        new_permissions = set(
            (r, p['name']) for p in new_data for r, v in p.items() if v)
        permissions_to_delete = old_permissions - new_permissions
        permissions_to_add = new_permissions - old_permissions
        log.info(f"{permissions_to_delete=} {permissions_to_add=}")

        for permission in permissions_to_add:
            auth.set_permission_for_role(*permission, mode='default')
        for permission in permissions_to_delete:
            auth.remove_permission_from_role(*permission, mode='default')
        return {"ok": True}


class PublicProjectAPI(api_tools.APIModeHandler):
    @auth.decorators.check_api({
        "permissions": ["configuration.roles.permissions.view"],
        "recommended_roles": {
            "administration": {"admin": True, "viewer": False, "editor": False},
            "default": {"admin": True, "viewer": False, "editor": False},
        }}, mode="administration")
    def get(self, target_mode):
        project_id = self._get_public_project_id()
        if project_id is None:
            return {"error": "Public project not configured"}, 404
        roles = auth.list_project_roles(project_id)
        role_map = {r['id']: r['name'] for r in roles}
        overrides = auth.list_project_role_permissions(project_id)
        
        all_permissions = list(auth.local_permissions)
        all_permissions = filter_permissions(all_permissions, target_mode)
        
        if overrides:
            roles_to_perms = {r['name']: set() for r in roles}
            for entry in overrides:
                role_name = role_map.get(entry['role_id'])
                if role_name and role_name in roles_to_perms:
                    roles_to_perms[role_name].add(entry['permission'])
            all_permissions = sorted(all_permissions)
            return {
                "total": len(all_permissions),
                "rows": [{
                    "name": p,
                    **{rn: p in perms for rn, perms in roles_to_perms.items()}
                } for p in all_permissions]
            }
        # No overrides — show central defaults
        central = auth.get_permissions(mode='default')
        roles_to_perms = group_roles_by_permissions(central, roles)
        all_permissions = sorted(all_permissions)
        return {
            "total": len(all_permissions),
            "rows": [{
                "name": p,
                **{r['name']: p in roles_to_perms[r['name']] for r in roles}
            } for p in all_permissions]
        }

    @auth.decorators.check_api({
        "permissions": ["configuration.roles.permissions.edit"],
        "recommended_roles": {
            "administration": {"admin": True, "viewer": False, "editor": False},
            "default": {"admin": True, "viewer": False, "editor": False},
        }}, mode="administration")
    def put(self, target_mode):
        project_id = self._get_public_project_id()
        if project_id is None:
            return {"error": "Public project not configured"}, 404
        new_data = request.get_json()
        roles = auth.list_project_roles(project_id)
        role_name_to_id = {r['name']: r['id'] for r in roles}
        # Clear existing overrides
        existing = auth.list_project_role_permissions(project_id)
        for entry in existing:
            auth.delete_project_role_permission(
                project_id, entry['role_id'], entry['permission'],
            )
        # Insert new permissions
        for row in new_data:
            perm_name = row.get('name')
            if not perm_name:
                continue
            for role_name, role_id in role_name_to_id.items():
                if row.get(role_name):
                    auth.add_project_role_permission(project_id, role_id, perm_name)
        return {"ok": True}

    @staticmethod
    def _get_public_project_id():
        from tools import elitea_config  # pylint: disable=C0415,E0401
        pid = elitea_config.get("ai_project_id")
        return int(pid) if pid is not None else None


class API(api_tools.APIBase):  # pylint: disable=R0903
    url_params = [
        "<string:target_mode>",
        "<string:mode>/<string:target_mode>",
        "<string:mode>/<int:project_id>",
    ]

    mode_handlers = {
        'default': ProjectAPI,
        'administration': AdminAPI,
        'public': PublicProjectAPI,
    }
