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
from pylon.core.tools import config  # pylint: disable=E0611,E0401,W0611

from tools import auth  # pylint: disable=E0401
from tools import api_tools, register_openapi  # pylint: disable=E0401
from tools import context  # pylint: disable=E0401


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=R0903
    """ API """

    @register_openapi(
        name="Get Pylon Splash Template",
        description="Get the maintenance splash screen template for a pylon.",
        parameters=[
            {"name": "target_pylon_id", "in": "path", "schema": {"type": "string"},
             "description": "Target pylon identifier (must match current pylon)."},
        ],
    )
    @auth.decorators.check_api(["runtime.plugins"])
    def get(self, target_pylon_id):
        """ Process GET """
        if context.id != target_pylon_id:
            return {"error": "Only main pylon supported"}, 400
        #
        return {"splash": config.tunable_get("splash_template", b"").decode()}

    @register_openapi(
        name="Save Pylon Splash Template",
        description="Save the maintenance splash screen template for a pylon.",
        parameters=[
            {"name": "target_pylon_id", "in": "path", "schema": {"type": "string"},
             "description": "Target pylon identifier (must match current pylon)."},
        ],
    )
    @auth.decorators.check_api(["runtime.plugins"])
    def post(self, target_pylon_id):
        """ Process POST """
        data = flask.request.get_json()
        #
        action = data.get("action", None)
        #
        if context.id != target_pylon_id or action != "save":
            return {"error": "Only main pylon splash save supported"}, 400
        #
        if "data" in data and data["data"]:
            log.info("Saving splash template")
            config.tunable_set("splash_template", data["data"].encode())
        #
        return {"ok": True}


class API(api_tools.APIBase):  # pylint: disable=R0903
    """ API """

    url_params = [
        "<string:mode>/<string:target_pylon_id>",
    ]

    mode_handlers = {
        'administration': AdminAPI,
    }
