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

""" Task """

import time

from tools import context  # pylint: disable=E0401

from .logs import make_logger


SUPER_ADMIN_ONLY_PERMISSIONS = {
    "configuration.advanced",
    "configuration.service_descriptors",
    "admin.auth.users.super_admin",
}


def migrate_admin_to_super_admin(*args, **kwargs):
    """Migrate 'admin' role to 'super_admin' in administration mode and create new limited 'admin'. No params."""
    #
    with make_logger() as log:
        log.info("Starting admin -> super_admin migration")
        start_ts = time.time()
        #
        try:
            rpc = context.rpc_manager.call
            #
            mode = "administration"
            #
            # Check if super_admin already exists (idempotency)
            #
            existing_roles = rpc.auth_get_roles(mode=mode)
            role_names = {r["name"] for r in existing_roles}
            #
            if "super_admin" in role_names:
                log.info("Role 'super_admin' already exists, skipping creation")
            else:
                log.info("Creating 'super_admin' role in '%s' mode", mode)
                rpc.auth_add_role(name="super_admin", mode=mode)
            #
            # Copy all permissions from admin to super_admin
            #
            admin_perms_data = rpc.auth_get_permissions_by_role("admin", mode=mode)
            admin_permissions = {item["permission"] for item in admin_perms_data if item.get("permission")}
            #
            super_admin_perms_data = rpc.auth_get_permissions_by_role("super_admin", mode=mode)
            super_admin_permissions = {item["permission"] for item in super_admin_perms_data if item.get("permission")}
            #
            missing_perms = admin_permissions - super_admin_permissions
            if missing_perms:
                log.info("Copying %d permissions from admin to super_admin", len(missing_perms))
                for perm in sorted(missing_perms):
                    try:
                        rpc.auth_set_permission_for_role("super_admin", perm, mode=mode)
                    except Exception:  # pylint: disable=W0703
                        log.warning("Failed to copy permission '%s' to super_admin", perm)
            else:
                log.info("super_admin already has all admin permissions")
            #
            # Add super_admin-only permissions
            #
            for perm in sorted(SUPER_ADMIN_ONLY_PERMISSIONS):
                if perm not in super_admin_permissions:
                    try:
                        rpc.auth_set_permission_for_role("super_admin", perm, mode=mode)
                        log.info("Added super_admin-only permission: %s", perm)
                    except Exception:  # pylint: disable=W0703
                        log.warning("Failed to add permission '%s' to super_admin", perm)
            #
            # Reassign all admin users to super_admin
            #
            log.info("Reassigning users from admin to super_admin")
            users = rpc.auth_list_users()
            reassigned = 0
            #
            for user in users:
                user_id = user["id"]
                user_roles = rpc.auth_get_user_roles(user_id, mode=mode)
                #
                if "admin" in user_roles:
                    # Assign super_admin (skip if already assigned)
                    try:
                        rpc.auth_assign_user_to_role(
                            user_id=user_id,
                            role_name="super_admin",
                            mode=mode,
                        )
                    except Exception:  # pylint: disable=W0703
                        log.info("User %s already has super_admin role, skipping assign", user_id)
                    #
                    # Remove admin role
                    try:
                        rpc.auth_remove_user_from_role(
                            user_id=user_id,
                            role_name="admin",
                            mode=mode,
                        )
                        reassigned += 1
                        log.info("Reassigned user %s from admin to super_admin", user_id)
                    except Exception:  # pylint: disable=W0703
                        log.warning("Failed to remove admin role from user %s", user_id, exc_info=True)
            #
            log.info("Reassigned %d users from admin to super_admin", reassigned)
            #
            # Remove super_admin-only permissions from admin role
            #
            log.info("Removing super_admin-only permissions from admin role")
            for perm in sorted(SUPER_ADMIN_ONLY_PERMISSIONS):
                if perm in admin_permissions:
                    try:
                        rpc.auth_remove_permission_from_role("admin", perm, mode=mode)
                        log.info("Removed permission '%s' from admin", perm)
                    except Exception:  # pylint: disable=W0703
                        log.warning("Failed to remove permission '%s' from admin", perm)
            #
        except:  # pylint: disable=W0702
            log.exception("Got exception, stopping")
        #
        end_ts = time.time()
        log.info("Exiting (duration = %s)", end_ts - start_ts)
