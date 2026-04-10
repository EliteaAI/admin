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
import yaml  # pylint: disable=E0401

from pylon.core.tools import log  # pylint: disable=E0611,E0401,W0611

from tools import auth  # pylint: disable=E0401
from tools import api_tools  # pylint: disable=E0401


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=R0903
    """ API """

    @auth.decorators.check_api(["runtime.plugins"])
    def get(self, target_pylon_id):
        """ Process GET """
        for pylon_id in list(sorted(self.module.remote_runtimes.keys())):
            if pylon_id != target_pylon_id:
                continue
            #
            data = self.module.remote_runtimes[pylon_id]
            pylon_settings = data.get("pylon_settings", {})
            #
            if flask.request.args.get("raw", "false") == "true":
                config_data = pylon_settings.get("tunable", "")
            else:
                config_data = yaml.dump(pylon_settings.get("active", ""))
            #
            return {"config": config_data}
        #
        return {"config": ""}

    @auth.decorators.check_api(["runtime.plugins"])
    def post(self, target_pylon_id):
        """ Process POST """
        data = flask.request.get_json()
        #
        action = data.get("action", None)
        #
        if action == "restart":
            log.info("Requesting pylon restart: %s", target_pylon_id)
            #
            self.module.context.event_manager.fire_event(
                "bootstrap_runtime_update",
                {
                    "pylon_id": target_pylon_id,
                    "restart": True,
                    "pylon_pid": 1,
                },
            )
        #
        elif action == "save":
            if "data" in data and data["data"]:
                log.info("Requesting pylon config update: %s", target_pylon_id)
                #
                self.module.context.event_manager.fire_event(
                    "bootstrap_runtime_update",
                    {
                        "pylon_id": target_pylon_id,
                        "actions": [
                            ["update_pylon_config", data["data"]],
                        ],
                        "restart": False,
                    },
                )
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
