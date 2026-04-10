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

import uuid
import json

import flask  # pylint: disable=E0401,W0611
import flask_restful  # pylint: disable=E0401

from pylon.core.tools import log  # pylint: disable=E0611,E0401,W0611

from tools import auth  # pylint: disable=E0401
from tools import theme  # pylint: disable=E0401
from tools import api_tools  # pylint: disable=E0401


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=R0903
    @auth.decorators.check_api(["modes.users"])
    def get(self):  # pylint: disable=R0201
        """ Process GET """
        result = list()
        #
        users = self.module.context.rpc_manager.call.auth_list_users()
        #
        for mode_key in theme.modes:
            for user in users:
                user_roles = self.module.context.rpc_manager.call.auth_get_user_roles(
                    user["id"], mode_key
                )
                #
                for role in user_roles:
                    result.append({
                        "id": f'{user["id"]}:{mode_key}:{role}',
                        "user_id": user["id"],
                        "user_email": user["email"],
                        "user_name": user["name"],
                        "mode": mode_key,
                        "role": role,
                    })
        #
        return {
            "total": len(result),
            "rows": result,
        }

    @auth.decorators.check_api(["modes.users"])
    def post(self):  # pylint: disable=R0201
        """ Process POST """
        data = flask.request.get_json()  # TODO: validation with pydantic
        #
        try:
            user_id = int(data["user_id"])
        except:  # pylint: disable=W0702
            user_email = data["user_id"]
            user = auth.get_user(email=user_email)
            user_id = user["id"]
        #
        mode = data["mode"]
        role = data["role"]
        #
        self.module.context.rpc_manager.call.auth_assign_user_to_role(
            user_id, role, mode
        )
        #
        return {"ok": True}

    @auth.decorators.check_api(["modes.users"])
    def delete(self):  # pylint: disable=R0201
        """ Process DELETE """
        data = flask.request.args  # TODO: validation with pydantic
        #
        items = data["id"].split(":")
        #
        user_id = int(items[0])
        mode = items[1]
        role = items[2]
        #
        # TODO: RPC in auth_core
        #
        return {"ok": True}


class API(api_tools.APIBase):  # pylint: disable=R0903
    url_params = [
        "<string:mode>",
    ]

    mode_handlers = {
        'administration': AdminAPI,
    }
