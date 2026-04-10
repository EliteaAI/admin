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
from tools import api_tools  # pylint: disable=E0401
from tools import context  # pylint: disable=E0401


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=R0903
    """ API """

    def _get_splash_enabled(self):
        """ Check if splash is enabled on the main pylon """
        try:
            module_manager = self.module.context.module_manager
            if "bootstrap" in module_manager.descriptors:
                return module_manager.descriptors["bootstrap"].state.get(
                    "splash_enabled", False,
                )
        except:  # pylint: disable=W0702
            log.exception("Failed to read splash state")
        return False

    @auth.decorators.check_api(["runtime.plugins"])
    def get(self):
        """ Get maintenance status and splash template """
        enabled = self._get_splash_enabled()
        splash_html = config.tunable_get("splash_template", b"").decode()
        #
        return {
            "enabled": enabled,
            "splash_template": splash_html,
            "pylon_id": context.id,
        }

    @auth.decorators.check_api(["runtime.plugins"])
    def put(self):
        """ Update maintenance settings """
        data = flask.request.get_json()
        #
        # Handle enable/disable toggle
        if "enabled" in data:
            action = "enable_splash" if data["enabled"] else "disable_splash"
            log.info("Maintenance splash: %s", action)
            self.module.context.event_manager.fire_event(
                "bootstrap_runtime_update",
                {
                    "pylon_id": context.id,
                    "actions": [action],
                    "restart": False,
                },
            )
        #
        # Handle splash template update
        if "splash_template" in data and data["splash_template"]:
            log.info("Saving splash template")
            config.tunable_set(
                "splash_template", data["splash_template"].encode(),
            )
        #
        enabled = self._get_splash_enabled()
        #
        return {"ok": True, "enabled": enabled}


class API(api_tools.APIBase):  # pylint: disable=R0903
    """ API """

    url_params = [
        "<string:mode>",
    ]

    mode_handlers = {
        'administration': AdminAPI,
    }
