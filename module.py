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

""" Module """
from pylon.core.tools import log  # pylint: disable=E0401
from pylon.core.tools import module  # pylint: disable=E0401

from tools import VaultClient  # pylint: disable=E0401
import hvac


class ThemeStub:
    """Minimal theme replacement when theme plugin is not loaded."""

    def __init__(self):
        self.modes = {}
        self.sections = {}
        self.subsections = {}
        self.pages = {}
        self.mode_sections = {}
        self.mode_subsections = {}
        self.mode_pages = {}
        self.mode_landing = {}
        self.landing = {"kind": "holder"}

    @property
    def access_denied_part(self):
        return ""

    @property
    def empty_content(self):
        return ""

    def register_mode(self, key, name, permissions=None, weight=1, **kwargs):
        from tools import auth  # pylint: disable=E0401,C0415
        permissions = permissions or []
        auth.update_local_permissions(permissions)
        self.modes[key] = {
            "name": name, "permissions": permissions, "weight": weight, **kwargs,
        }

    def register_mode_landing(self, mode, **kwargs):
        self.mode_landing[mode] = kwargs

    def register_mode_section(self, mode, key, name, permissions=None, **kwargs):
        from tools import auth  # pylint: disable=E0401,C0415
        permissions = permissions or []
        auth.update_local_permissions(permissions)

    def register_mode_subsection(self, mode, section, key, name, permissions=None, **kwargs):
        from tools import auth  # pylint: disable=E0401,C0415
        permissions = permissions or []
        auth.update_local_permissions(permissions)

    def register_mode_page(self, mode, section, subsection, key, permissions=None, **kwargs):
        from tools import auth  # pylint: disable=E0401,C0415
        permissions = permissions or []
        if isinstance(permissions, dict):
            auth.update_local_permissions(permissions)
        elif permissions:
            auth.update_local_permissions(permissions)

    def register_section(self, key, name, permissions=None, **kwargs):
        from tools import auth  # pylint: disable=E0401,C0415
        permissions = permissions or []
        auth.update_local_permissions(permissions)

    def register_subsection(self, section, key, name, permissions=None, **kwargs):
        from tools import auth  # pylint: disable=E0401,C0415
        permissions = permissions or []
        auth.update_local_permissions(permissions)

    def register_page(self, section, subsection, key, **kwargs):
        permissions = kwargs.get("permissions", [])
        if permissions:
            from tools import auth  # pylint: disable=E0401,C0415
            auth.update_local_permissions(permissions)

    def get_visible_sections(self):
        return []

    def get_visible_subsections(self, section):
        return []

    def get_visible_plugins(self):
        return []


class Module(module.ModuleModel):
    """ Pylon module """

    def __init__(self, context, descriptor):
        self.context = context
        self.descriptor = descriptor
        #
        # Register ThemeStub if theme plugin is not loaded.
        # Must happen in __init__ (not preload) because other plugins
        # import theme at module level during their import step.
        #
        module_manager = self.context.module_manager
        if "theme" not in module_manager.modules:
            self.descriptor.register_tool('theme', ThemeStub())
        #
        # self.db = Holder()  # pylint: disable=C0103
        # self.db.tbl = Holder()
        #
        self.remote_runtimes = {}

    def init(self):
        """ Init module """
        log.info("Initializing module")
        from tools import theme  # pylint: disable=E0401,C0415
        from tools import auth  # pylint: disable=E0401,C0415
        # Run DB migrations
        # db_migrations.run_db_migrations(self, db.url)
        # DB
        # Theme registration
        #
        # System: for landing info screen
        #
        theme.register_section(
            "system", "System",
            kind="holder",
            hidden=True,
            location="left",
            permissions=[],
            # icon_class="fas fa-info-circle fa-fw",
        )
        theme.register_subsection(
            "system",
            "status", "Status",
            title="Status",
            kind="slot",
            hidden=True,
            permissions=[],
            prefix="admin_system_status_",
            # icon_class="fas fa-server fa-fw",
            # weight=2,
        )
        theme.register_page(
            "system", "status", "empty",
            title="Empty",
            kind="slot",
            permissions=[],
            prefix="admin_system_status_empty_",
        )
        #
        # Administration mode
        #
        theme.register_mode(
            "administration", "Administration",
        )
        theme.register_mode_section(
            "administration", "projects", "Projects",
            kind="holder",
            location="left",
            permissions={
                "permissions": ["projects"],
                "recommended_roles": {
                    "administration": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                    "default": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                    "developer": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                }},
            # icon_class="fas fa-info-circle fa-fw",
        )
        theme.register_mode_subsection(
            "administration", "projects",
            "list", "Projects",
            title="Projects",
            kind="slot",
            permissions={
                "permissions": ["projects.projects"],
                "recommended_roles": {
                    "administration": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                    "default": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                    "developer": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                }},
            prefix="admin_mode_projects_",
            # icon_class="fas fa-server fa-fw",
            # weight=2,
        )
        theme.register_mode_page(
            "administration", "projects",
            "list", "edit",
            title="Edit",
            kind="slot",
            permissions={
                "permissions": ["projects.projects"],
                "recommended_roles": {
                    "administration": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                    "default": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                    "developer": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                }},
            prefix="admin_mode_projects_edit_",
        )
        #
        # Configuration (super_admin only)
        #
        theme.register_mode_section(
            "administration", "configuration", "Configuration",
            kind="holder",
            location="left",
            permissions={
                "permissions": ["configuration"],
                "recommended_roles": {
                    "administration": {"super_admin": True, "admin": True, "viewer": True, "editor": True},
                    "default": {"super_admin": True, "admin": True, "viewer": True, "editor": True},
                    "developer": {"super_admin": True, "admin": True, "viewer": True, "editor": True},
                }},
            # icon_class="fas fa-info-circle fa-fw",
        )
        #
        theme.register_mode_subsection(
            "administration", "configuration",
            "roles", "Roles",
            title="Roles",
            kind="slot",
            permissions={
                "permissions": ["configuration.roles"],
                "recommended_roles": {
                    "administration": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                    "default": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                    "developer": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                }},
            prefix="admin_mode_roles_",
            # icon_class="fas fa-server fa-fw",
            # weight=2,
        )
        theme.register_subsection(
            "configuration",
            "roles", "Roles",
            title="Roles",
            kind="slot",
            permissions={
                "permissions": ["configuration.roles"],
                "recommended_roles": {
                    "administration": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                    "default": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                    "developer": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                }},
            prefix="roles_",
        )
        theme.register_subsection(
            "configuration",
            "users", "Users",
            title="Users",
            kind="slot",
            permissions={
                "permissions": ["configuration.users"],
                "recommended_roles": {
                    "administration": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                    "default": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                    "developer": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                }},
            prefix="users_",
        )
        #
        # Modes
        #
        theme.register_mode_section(
            "administration", "modes", "Modes",
            kind="holder",
            permissions={
                "permissions": ["modes"],
                "recommended_roles": {
                    "administration": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                    "default": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                    "developer": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                }
            },
            location="left",
            icon_class="fas fa-info-circle fa-fw",
        )
        theme.register_mode_subsection(
            "administration", "modes",
            "users", "Users",
            title="Users",
            kind="slot",
            permissions={
                "permissions": ["modes.users"],
                "recommended_roles": {
                    "administration": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                    "default": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                    "developer": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                }
            },
            prefix="admin_modes_users_",
            icon_class="fas fa-server fa-fw",
        )
        #
        # Runtime (super_admin only)
        #
        theme.register_mode_section(
            "administration", "runtime", "Runtime",
            kind="holder",
            permissions={
                "permissions": ["runtime"],
                "recommended_roles": {
                    "administration": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
                    "default": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
                    "developer": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
                }
            },
            location="left",
            icon_class="fas fa-info-circle fa-fw",
        )
        # theme.register_mode_subsection(
        #     "administration", "runtime",
        #     "plugins", "Plugins",
        #     title="Plugins",
        #     kind="slot",
        #     permissions={
        #         "permissions": ["runtime.plugins"],
        #         "recommended_roles": {
        #             "administration": {"admin": True, "viewer": False, "editor": False},
        #             "default": {"admin": True, "viewer": False, "editor": False},
        #             "developer": {"admin": True, "viewer": False, "editor": False},
        #         }
        #     },
        #     prefix="admin_runtime_plugins_",
        #     icon_class="fas fa-server fa-fw",
        # )
        theme.register_mode_subsection(
            "administration", "runtime",
            "remote", "Remote",
            title="Remote",
            kind="slot",
            permissions={
                "permissions": ["runtime.plugins"],
                "recommended_roles": {
                    "administration": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
                    "default": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
                    "developer": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
                }
            },
            prefix="admin_runtime_remote_",
            icon_class="fas fa-server fa-fw",
        )
        theme.register_mode_subsection(
            "administration", "runtime",
            "pylons", "Pylons",
            title="Pylons",
            kind="slot",
            permissions={
                "permissions": ["runtime.plugins"],
                "recommended_roles": {
                    "administration": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
                    "default": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
                    "developer": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
                }
            },
            prefix="admin_runtime_pylons_",
            icon_class="fas fa-server fa-fw",
        )
        theme.register_mode_subsection(
            "administration", "runtime",
            "tasknodes", "TaskNodes",
            title="TaskNodes",
            kind="slot",
            permissions={
                "permissions": ["runtime.plugins"],
                "recommended_roles": {
                    "administration": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
                    "default": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
                    "developer": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
                }
            },
            prefix="admin_runtime_tasknodes_",
            icon_class="fas fa-server fa-fw",
        )
        #
        # Tasks (super_admin only)
        #
        theme.register_mode_section(
            "administration", "tasks", "Tasks",
            kind="holder",
            permissions={
                "permissions": ["runtime"],
                "recommended_roles": {
                    "administration": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
                    "default": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
                    "developer": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
                }
            },
            location="left",
            icon_class="fas fa-info-circle fa-fw",
        )
        theme.register_mode_subsection(
            "administration", "tasks",
            "tasks", "Tasks",
            title="Tasks",
            kind="slot",
            permissions={
                "permissions": ["runtime.plugins"],
                "recommended_roles": {
                    "administration": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
                    "default": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
                    "developer": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
                }
            },
            prefix="admin_tasks_tasks_",
            icon_class="fas fa-server fa-fw",
        )
        #
        # Migration (super_admin only)
        #
        theme.register_mode_section(
            "administration", "migration", "Migration",
            kind="holder",
            permissions={
                "permissions": ["migration"],
                "recommended_roles": {
                    "administration": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
                    "default": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
                    "developer": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
                }
            },
            location="left",
            icon_class="fas fa-info-circle fa-fw",
        )
        theme.register_mode_subsection(
            "administration", "migration",
            "db", "DB",
            title="DB",
            kind="slot",
            permissions={
                "permissions": ["migration.db"],
                "recommended_roles": {
                    "administration": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
                    "default": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
                    "developer": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
                }
            },
            prefix="admin_migration_db_",
            icon_class="fas fa-server fa-fw",
        )
        theme.register_mode_subsection(
            "administration", "migration",
            "permissions", "Permissions",
            title="Permissions",
            kind="slot",
            permissions={
                "permissions": ["migration.permissions"],
                "recommended_roles": {
                    "administration": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
                    "default": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
                    "developer": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
                }
            },
            prefix="admin_migration_permissions_",
            icon_class="fas fa-server fa-fw",
        )
        #
        # Invites
        #
        theme.register_mode_section(
            "administration", "invites", "Invites",
            kind="holder",
            permissions={
                "permissions": ["invites"],
                "recommended_roles": {
                    "administration": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                    "default": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                    "developer": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                }
            },
            location="left",
            icon_class="fas fa-info-circle fa-fw",
        )
        theme.register_mode_subsection(
            "administration", "invites",
            "platform", "Platform",
            title="Platform",
            kind="slot",
            permissions={
                "permissions": ["invites.platform"],
                "recommended_roles": {
                    "administration": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                    "default": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                    "developer": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                }
            },
            prefix="admin_invites_platform_",
            icon_class="fas fa-server fa-fw",
        )
        theme.register_mode_subsection(
            "administration", "invites",
            "bulkusers", "Bulk users",
            title="Bulk users",
            kind="slot",
            permissions={
                "permissions": ["invites.bulkusers"],
                "recommended_roles": {
                    "administration": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                    "default": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                    "developer": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                }
            },
            prefix="admin_invites_bulkusers_",
            icon_class="fas fa-server fa-fw",
        )
        theme.register_mode_subsection(
            "administration", "invites",
            "bulkprojects", "Bulk projects",
            title="Bulk projects",
            kind="slot",
            permissions={
                "permissions": ["invites.bulkprojects"],
                "recommended_roles": {
                    "administration": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                    "default": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                    "developer": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                }
            },
            prefix="admin_invites_bulkprojects_",
            icon_class="fas fa-server fa-fw",
        )
        #
        # Users
        #
        theme.register_mode_section(
            "administration", "users", "Users",
            kind="holder",
            permissions={
                "permissions": ["admin.auth.users"],
                "recommended_roles": {
                    "administration": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                    "default": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                    "developer": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                }
            },
            location="left",
            icon_class="fas fa-info-circle fa-fw",
        )
        theme.register_mode_subsection(
            "administration", "users",
            "users", "Users",
            title="Users",
            kind="slot",
            permissions={
                "permissions": ["admin.auth.users"],
                "recommended_roles": {
                    "administration": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                    "default": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                    "developer": {"super_admin": True, "admin": True, "viewer": False, "editor": False},
                }
            },
            prefix="admin_auth_users_",
            icon_class="fas fa-server fa-fw",
        )
        #
        # Super-admin only permissions
        #
        auth.register_permissions({
            "permissions": ["configuration.advanced"],
            "recommended_roles": {
                "administration": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
                "default": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
                "developer": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
            }
        })
        auth.register_permissions({
            "permissions": ["configuration.service_descriptors"],
            "recommended_roles": {
                "administration": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
                "default": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
                "developer": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
            }
        })
        auth.register_permissions({
            "permissions": ["admin.auth.users.super_admin"],
            "recommended_roles": {
                "administration": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
                "default": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
                "developer": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
            }
        })
        # Init
        self.descriptor.init_all()
        #
        vault_client = VaultClient()  # for administration mode
        vault_client.create_project_space(quiet=True)
        #
        secrets = vault_client.get_secrets()
        if "auth_token" not in secrets:
            #
            try:
                system_user_id = self.context.rpc_manager.call.auth_get_user(
                    email="system@centry.user",
                )["id"]
            except:  # pylint: disable=W0702
                system_user_id = None
            #
            if system_user_id is not None:
                all_tokens = self.context.rpc_manager.call.auth_list_tokens(
                    system_user_id
                )
                #
                if len(all_tokens) < 1:
                    token_id = self.context.rpc_manager.call.auth_add_token(
                        system_user_id, "api",
                    )
                else:
                    token_id = all_tokens[0]["id"]
                #
                token = self.context.rpc_manager.call.auth_encode_token(token_id)
                #
                secrets["auth_token"] = token
                vault_client.set_secrets(secrets)

    def ready(self):
        """ Ready callback """
        from tools import db, auth  # pylint: disable=C0415
        from .models.users import Role, RolePermission, UserRole
        from concurrent.futures import ThreadPoolExecutor

        #
        # Migration logic
        #
        check_migration = self.descriptor.config.get("check_for_roles_migration", False)
        force_migration = self.descriptor.config.get("force_role_migration", False)
        
        if check_migration or force_migration:
            log.info("Getting project list for roles migration check")
            project_list = self.context.rpc_manager.timeout(120).project_list(
                filter_={"create_success": True},
            )
            
            projects_to_process = []
            
            # Filter projects
            for project in project_list:
                p_id = project["id"]
                should_process = False
                
                if force_migration is True:
                    should_process = True
                elif isinstance(force_migration, list) and p_id in force_migration:
                    should_process = True
                elif check_migration:
                    # Check if already has roles, if so skip (unless forced)
                    # Optimization: check one role existence
                    if not auth.list_project_roles(p_id):
                        should_process = True
                
                if should_process:
                    projects_to_process.append(project)

            if not projects_to_process:
                return

            log.info("Migrating roles for %s projects", len(projects_to_process))

            #
            # Worker function to read project data
            #
            def get_project_data(project):
                p_id = project["id"]
                try:
                    with db.get_session(p_id) as tenant_db:
                        roles = []
                        assignments = []
                        
                        # Read Roles and Permissions
                        db_roles = tenant_db.query(Role).all()
                        role_map = {r.id: r.name for r in db_roles}
                        
                        for role in db_roles:
                            perms = [p.permission for p in role.permissions]
                            roles.append({
                                "name": role.name,
                                "permissions": perms
                            })
                        
                        # Read User Roles
                        db_user_roles = tenant_db.query(UserRole).all()
                        for ur in db_user_roles:
                            if ur.role_id in role_map:
                                assignments.append({
                                    "user_id": ur.user_id,
                                    "role": role_map[ur.role_id]
                                })
                        
                        return {
                            "project_id": p_id,
                            "roles": roles,
                            "assignments": assignments
                        }
                except:  # pylint: disable=W0702
                    log.warning("Failed to read project data for %s", p_id, exc_info=True)
                    return None

            #
            # Parallel Execution
            #
            max_workers = self.descriptor.config.get("role_migration_threads", 1)
            batch_size = self.descriptor.config.get("role_migration_batch_size", 10)
            snapshot_batch = []
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(get_project_data, p): p for p in projects_to_process}
                
                for future in futures:
                    data = future.result()
                    if data:
                        snapshot_batch.append(data)
                        
                    # Apply in batches of e.g. 50 (or just all at once if memory permits, but safer to batch)
                    if len(snapshot_batch) >= batch_size:
                        log.info("Uploading batch of %s project snapshots", len(snapshot_batch))
                        auth.apply_project_roles_snapshot(snapshot_batch)
                        snapshot_batch = []
            
            # Apply remaining
            if snapshot_batch:
                log.info("Uploading batch of %s project snapshots", len(snapshot_batch))
                auth.apply_project_roles_snapshot(snapshot_batch)
            
            log.info("Roles migration finished")
        #
        # Schedule: weekly auth token rotation
        #
        try:
            self.context.rpc_manager.timeout(5).scheduling_create_if_not_exists({
                'name': 'rotate_auth_tokens',
                'cron': '0 2 * * 0',  # Sunday 02:00
                'rpc_func': 'admin_rotate_tokens',
                'rpc_kwargs': {},
                'active': True,
            })
        except Exception:  # pylint: disable=W0703
            log.warning("Could not register token rotation schedule", exc_info=True)

    def deinit(self):  # pylint: disable=R0201
        """ De-init module """
        log.info("De-initializing module")
        # De-init
        # self.descriptor.deinit_all()
