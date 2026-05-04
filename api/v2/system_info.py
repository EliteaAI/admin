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

""" API: system info for the Information card on the Resources page """

import os
import time

try:
    from importlib.metadata import version as _pkg_version
    _PYLON_VERSION = _pkg_version("pylon")
except Exception:  # pylint: disable=W0703
    _PYLON_VERSION = ""

from tools import auth  # pylint: disable=E0401
from tools import api_tools  # pylint: disable=E0401


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=R0903
    """ API """

    @auth.decorators.check_api(["runtime.plugins"])
    def get(self):
        """ Process GET """
        _release = os.environ.get("ELITEA_RELEASE", "")
        # "release/2.0.2" -> "2.0.2", "main" -> "main"
        elitea_version = _release.removeprefix("release/") if _release else ""

        pylons = []

        for pylon_id in sorted(self.module.remote_runtimes.keys()):
            data = self.module.remote_runtimes[pylon_id]

            if time.time() - data.get("timestamp", 0) > 60:
                continue

            # Human-readable pylon name from server.name in pylon.yml
            pylon_name = (
                data.get("pylon_settings", {})
                    .get("active", {})
                    .get("server", {})
                    .get("name", pylon_id[:8])
            )

            # Find the *core* plugin version for this pylon
            runtime_info = data.get("runtime_info", [])
            core_version = None

            for plugin in runtime_info:
                plugin_name = plugin.get("name", "")
                if "_core" in plugin_name:
                    core_version = plugin.get("local_version", "")
                    break

            pylons.append({
                "pylon_id": pylon_id,
                "name": pylon_name,
                "core_version": core_version,
            })

        return {
            "elitea_version": elitea_version,
            "pylon_version": _PYLON_VERSION,
            "pylons": pylons,
        }


class API(api_tools.APIBase):  # pylint: disable=R0903
    """ API """

    url_params = [
        "<string:mode>",
    ]

    mode_handlers = {
        "administration": AdminAPI,
    }
