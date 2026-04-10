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

import time
import flask  # pylint: disable=E0401,W0611

from pylon.core.tools import log  # pylint: disable=E0611,E0401,W0611

from tools import auth  # pylint: disable=E0401
from tools import api_tools  # pylint: disable=E0401


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=R0903
    """ API """

    @auth.decorators.check_api(["runtime.plugins"])
    def get(self):
        """ Process GET """
        result = []
        #
        for pylon_id in list(sorted(self.module.remote_runtimes.keys())):
            data = self.module.remote_runtimes[pylon_id]
            #
            if time.time() - data["timestamp"] > 60:  # 4 announces missing (for 15s interval)
                self.module.remote_runtimes.pop(pylon_id, None)
                continue
            #
            result.append({"pylon_id": pylon_id})
        #
        return {
            "total": len(result),
            "rows": result,
        }

    @auth.decorators.check_api(["runtime.plugins"])
    def post(self):
        """ Process POST """
        data = flask.request.get_json()
        #
        pylon_id = data.get("pylon_id", None)
        action = data.get("action", None)
        #
        if pylon_id and action:
            self.module.context.event_manager.fire_event(
                "bootstrap_runtime_update",
                {
                    "pylon_id": pylon_id,
                    "actions": [action],
                    "restart": False,
                },
            )
        #
        if not pylon_id:
            return {"ok": True, "logs": ""}
        #
        if pylon_id not in self.module.remote_runtimes:
            return {"ok": True, "logs": ""}
        #
        data = self.module.remote_runtimes[pylon_id]
        return {"ok": True, "logs": "\n".join(data.get("logs", []))}


class API(api_tools.APIBase):  # pylint: disable=R0903
    """ API """

    url_params = [
        "<string:mode>",
    ]

    mode_handlers = {
        'administration': AdminAPI,
    }
