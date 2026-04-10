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
    @auth.decorators.check_api(["runtime.plugins"])
    def get(self):  # pylint: disable=R0201
        """ Process GET """
        result = list()
        #
        module_manager = self.module.context.module_manager
        #
        # NOTE: currently displaying only running plugins
        # NOTE: should use plugin provider to display e.g. failed plugins
        #
        for descriptor in module_manager.modules.values():
            result.append({
                "name": descriptor.name,
                "description": descriptor.metadata.get("name", ""),
                # "enabled": True,
                "prepared": descriptor.prepared,
                "activated": descriptor.activated,
                "local_version": descriptor.metadata.get("version", "0.0.0"),
                "repo_version": "-",
            })
        #
        return {
            "total": len(result),
            "rows": result,
        }

    # @auth.decorators.check_api(["runtime.plugins"])
    # def post(self):  # pylint: disable=R0201
    #     """ Process POST """
    #     data = flask.request.get_json()  # TODO: validation with pydantic
    #     #
    #     try:
    #         user_id = int(data["user_id"])
    #     except:  # pylint: disable=W0702
    #         user_email = data["user_id"]
    #         user = auth.get_user(email=user_email)
    #         user_id = user["id"]
    #     #
    #     mode = data["mode"]
    #     role = data["role"]
    #     #
    #     self.module.context.rpc_manager.call.auth_assign_user_to_role(
    #         user_id, role, mode
    #     )
    #     #
    #     return {"ok": True}

    # @auth.decorators.check_api(["runtime.plugins"])
    # def delete(self):  # pylint: disable=R0201
    #     """ Process DELETE """
    #     data = flask.request.args  # TODO: validation with pydantic
    #     #
    #     items = data["id"].split(":")
    #     #
    #     user_id = int(items[0])
    #     mode = items[1]
    #     role = items[2]
    #     #
    #     # TODO: RPC in auth_core
    #     #
    #     return {"ok": True}


class API(api_tools.APIBase):  # pylint: disable=R0903
    url_params = [
        "<string:mode>",
    ]

    mode_handlers = {
        'administration': AdminAPI,
    }
