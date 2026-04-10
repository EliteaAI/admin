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

    @auth.decorators.check_api(["invites.bulkusers"])
    def post(self):  # pylint: disable=R0912,R0914,R0915
        """ Process POST """
        data = flask.request.get_json()
        #
        if "project_id" not in data:
            return {"error": "project_id not set"}, 400
        #
        if "roles" not in data:
            return {"error": "roles not set"}, 400
        #
        logs = []
        #
        project_id = int(data["project_id"])
        new_roles = [item.strip() for item in data["roles"].split(",")]
        #
        for user in auth.list_users():
            log.debug("User: %s", user)
            #
            user_id = user["id"]
            user_name = user["name"]
            #
            if user_name is not None and user_name.startswith(":system:project:"):
                logs.append(f"Skipping user {user_id} ({user_name})")
                continue
            #
            self.module.admin_update_roles_for_user(project_id, user_id, new_roles)
            logs.append(f"Added user {user_id} ({user_name}) to {project_id} as {new_roles}")
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
