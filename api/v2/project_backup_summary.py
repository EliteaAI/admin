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

from tools import auth, api_tools, register_openapi  # pylint: disable=E0401

from .project_backup import PROJECT_DOWNLOAD_PERMISSION, PROMPT_LIB_MODE, make_chat_summary


class PromptLibAPI(api_tools.APIModeHandler):  # pylint: disable=R0903
    """ API """

    @register_openapi(
        name="Project Backup Chat Summary",
        description="Number of chats and attachment files, and their total size, that a "
                    "project backup with chats would carry for the caller.",
        parameters=[
            {"name": "project_id", "in": "path", "schema": {"type": "integer"},
             "description": "Project ID to back up."},
        ],
    )
    @auth.decorators.check_api({
        "permissions": [PROJECT_DOWNLOAD_PERMISSION],
        "recommended_roles": {
            "administration": {"super_admin": True, "admin": True, "viewer": False, "editor": True},
            "default": {"super_admin": True, "admin": True, "viewer": False, "editor": True},
        }})
    def get(self, project_id: int, **kwargs):
        """ Process GET """
        _ = kwargs
        return make_chat_summary(project_id, auth.current_user())


class API(api_tools.APIBase):  # pylint: disable=R0903
    """ API """

    url_params = [
        "<string:mode>/<int:project_id>",
    ]

    mode_handlers = {
        PROMPT_LIB_MODE: PromptLibAPI,
    }
