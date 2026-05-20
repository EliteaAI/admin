from collections import defaultdict
from typing import Optional, List

from flask import g

from tools import rpc_tools, db, db_tools, auth

from pylon.core.tools import web, log


class RPC:

    #
    # project_role
    #

    @web.rpc("admin_get_roles", "get_roles")
    def get_roles(self, project_id: int, **kwargs) -> list[dict]:
        return auth.list_project_roles(project_id)

    @web.rpc("admin_get_role", "get_role")
    def get_role(self, project_id: int, role_name: str, **kwargs) -> Optional[dict]:
        return auth.get_project_role(project_id, name=role_name)

    @web.rpc("admin_add_role", "add_role")
    def add_role(self, project_id: int, role_names: list[str], **kwargs) -> dict:
        last_role = None
        for role_name in role_names:
            role_id = auth.add_project_role(project_id, role_name)
            last_role = auth.get_project_role(project_id, id_=role_id)
        return last_role

    @web.rpc("admin_delete_role", "delete_role")
    def delete_role(self, project_id: int, role_name: str, **kwargs) -> bool:
        auth.delete_project_role(project_id, name=role_name)
        return True

    @web.rpc("admin_update_role_name", "update_role_name")
    def update_role_name(self, project_id: int, role_name: str, new_role_name: str, **kwargs) -> bool:
        role = auth.get_project_role(project_id, name=role_name)
        if role:
            auth.update_project_role(project_id, role['id'], new_role_name)
        return True

    #
    # project_role_permission
    #

    @web.rpc("admin_get_permissions", "get_permissions")
    def get_permissions(self, project_id: int, **kwargs) -> list[dict]:
        roles = auth.list_project_roles(project_id)
        project_role_names = {r['name'] for r in roles}
        central_permissions = auth.get_permissions(mode='default')
        return [p for p in central_permissions if p['name'] in project_role_names]

    @web.rpc("admin_set_permission_for_role", "set_permission_for_role")
    def set_permission_for_role(
            self, project_id: int, role_name: str, permission: str
    ) -> None:
        pass

    @web.rpc("admin_set_permissions_for_role", "set_permissions_for_role")
    def set_permissions_for_role(
            self, project_id: int, role_name: str, permissions: List[str],
            session=None, commit: bool = True
    ) -> None:
        pass

    @web.rpc("admin_get_permissions_for_role", "get_permissions_for_role")
    def get_permissions_for_role(
            self, project_id: int, role_name: str,
    ) -> List[str]:
        return [p['permission'] for p in auth.get_permissions(mode='default') if p['name'] == role_name]

    @web.rpc("admin_add_permissions_for_role", "add_permissions_for_role")
    def add_permissions_for_role(
            self, project_id: int, role_name: str, permissions: List[str],
    ) -> bool:
        return True

    @web.rpc("admin_remove_permission_from_role", "remove_permission_from_role")
    def remove_permission_from_role(
            self, project_id: int, role_name: str, permission: str
    ) -> bool:
        return True

    #
    # project_user_role
    #

    @web.rpc("admin_add_user_to_project", "add_user_to_project")
    def add_user_to_project(self, project_id: int, user_id: int, role_names: list[str], **kwargs) -> bool:
        user_roles = auth.list_project_user_roles(project_id, user_id)
        existing_role_ids = {r['role_id'] for r in user_roles}
        for role_name in role_names:
            role = auth.get_project_role(project_id, name=role_name)
            if role and role['id'] not in existing_role_ids:
                auth.add_project_user_role(project_id, user_id, role['id'])
        return True

    @web.rpc("admin_remove_users_from_project", "remove_users_from_project")
    def remove_users_from_project(self, project_id: int, user_ids: list[int], **kwargs) -> bool:
        for user_id in user_ids:
            auth.update_project_user_roles(project_id, user_id, [])
        return True

    @web.rpc("admin_get_permissions_in_project", "get_permissions_in_project")
    def get_permissions_in_project(self, project_id: int, user_id: int, **kwargs) -> set[str]:
        return auth.get_project_user_permissions(project_id, user_id)

    @web.rpc("admin_get_users_ids_in_project", "get_users_ids_in_project")
    def get_users_ids_in_project(self, project_id: int, filter_system_user: bool = False, **kwargs) -> list[int]:
        users = auth.list_project_users(project_id)
        if filter_system_user:
            system_user = self.get_project_system_user(project_id)
            if system_user and int(system_user['id']) in users:
                users.remove(int(system_user['id']))
        return users

    @web.rpc("admin_get_users_roles_in_project", "get_users_roles_in_project")
    def get_users_roles_in_project(self, project_id: int, filter_system_user: bool = False, **kwargs) -> dict[list]:
        user_roles_data = auth.list_project_user_roles(project_id)
        roles_data = auth.list_project_roles(project_id)
        role_map = {r['id']: r['name'] for r in roles_data}

        user_roles = defaultdict(list)
        for ur in user_roles_data:
            if ur['role_id'] in role_map:
                user_roles[ur['user_id']].append(role_map[ur['role_id']])

        if filter_system_user:
            system_user = self.get_project_system_user(project_id)
            if system_user and int(system_user['id']) in user_roles:
                del user_roles[int(system_user['id'])]
        return user_roles

    @web.rpc("update_roles_for_user", "admin_update_roles_for_user")
    def update_roles_for_user(self, project_id: int, user_ids: List[int], new_roles: List[str], **kwargs) -> bool:
        roles_data = auth.list_project_roles(project_id)
        role_name_map = {r['name']: r['id'] for r in roles_data}
        target_role_ids = []
        for name in new_roles:
            if name in role_name_map:
                target_role_ids.append(role_name_map[name])

        for user_id in user_ids:
            auth.update_project_user_roles(project_id, user_id, target_role_ids)
        return True

    @web.rpc("admin_get_user_roles", "get_user_roles")
    def get_user_roles(self, project_id: int, user_id: int) -> list[dict]:
        assert project_id is not None, 'project_id cannot be None'
        user_roles_data = auth.list_project_user_roles(project_id, user_id)
        my_role_ids = {ur['role_id'] for ur in user_roles_data}
        roles_data = auth.list_project_roles(project_id)
        return [r for r in roles_data if r['id'] in my_role_ids]

    @web.rpc("admin_check_user_is_admin", "check_user_is_admin")
    def check_user_is_admin(self, project_id: int, user_id: int) -> bool:
        user_roles_data = auth.list_project_user_roles(project_id, user_id)
        my_role_ids = {ur['role_id'] for ur in user_roles_data}
        roles_data = auth.list_project_roles(project_id)
        for r in roles_data:
            if r['id'] in my_role_ids and 'admin' in r['name'].lower():
                return True
        return False

    @web.rpc('admin_check_user_in_project', 'check_user_in_project')
    def check_user_in_project(self, project_id: int, user_id: Optional[int] = None, **kwargs) -> bool:
        if not user_id:
            log.info('User is None. Trying to get user from flask.g ...')
            try:
                user_id = int(g.auth.id)
            except (AttributeError, TypeError, ValueError):
                return False
        return auth.check_user_in_project(project_id, user_id)

    @web.rpc('admin_check_user_in_projects', 'check_user_in_projects')
    def check_user_in_projects(self, project_ids: list[int], user_id: Optional[int] = None, **kwargs) -> list[int]:
        if not user_id:
            log.info('User is None. Trying to get user from flask.g ...')
            try:
                user_id = int(g.auth.id)
            except (AttributeError, TypeError, ValueError):
                return []
        return auth.check_user_in_projects(project_ids, user_id)

    @web.rpc('admin_get_project_system_user', 'get_project_system_user')
    def get_project_system_user(self, project_id: int, **kwargs) -> Optional[dict]:
        from tools import project_constants as pc
        try:
            return auth.get_user(email=pc['PROJECT_USER_EMAIL_TEMPLATE'].format(project_id))
        except (RuntimeError):
            ...
        return

    @web.rpc('admin_get_distinct_user_ids', 'get_distinct_user_ids')
    def get_distinct_user_ids(self, project_id: int, **kwargs) -> List[int]:
        return auth.list_project_users(project_id)
