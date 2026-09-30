#!/usr/bin/python3
# coding=utf-8

#   Copyright 2025 EPAM Systems
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

""" RPC — auth token rotation """

from pylon.core.tools import web  # pylint: disable=E0611,E0401

from ..utils import system_tokens


class RPC:

    @web.rpc("admin_rotate_tokens", "rotate_tokens")
    def rotate_tokens(self, keep_previous=True):  # pylint: disable=R0201
        """Rotate auth tokens for the admin space and all projects; keep_previous=False is a hard cut."""
        system_tokens.rotate_admin_token(keep_previous)
        system_tokens.rotate_project_tokens(keep_previous)

    @web.rpc("admin_rotate_admin_token", "rotate_admin_token")
    def rotate_admin_token(self, keep_previous=True):  # pylint: disable=R0201
        """Rotate the admin-level auth_token (system@centry.user)."""
        system_tokens.rotate_admin_token(keep_previous)

    @web.rpc("admin_rotate_project_tokens", "rotate_project_tokens")
    def rotate_project_tokens(self, keep_previous=True):  # pylint: disable=R0201
        """Rotate auth tokens for all projects."""
        system_tokens.rotate_project_tokens(keep_previous)

    @web.rpc("admin_get_project_system_token", "get_project_system_token")
    def get_project_system_token(self, project_id, create_if_not_exists=True):  # pylint: disable=R0201
        """Encoded current 'api' token of the project system user, or None; the one pick rule rotation relies on."""
        return system_tokens.project_system_token(project_id, create_if_not_exists)
