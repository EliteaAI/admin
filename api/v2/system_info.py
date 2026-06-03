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

import time

from tools import auth  # pylint: disable=E0401
from tools import api_tools, register_openapi  # pylint: disable=E0401


_PRIORITY_PLUGINS = [
    "elitea_core",
    "admin",
    "notifications",
    "configurations",
    "sdk_plugin",
    "indexer_worker",
]


def _collect_plugin_versions(remote_runtimes):
    """ Collect versions for priority plugins across all active pylons """
    seen = {}
    for pylon_id in sorted(remote_runtimes.keys()):
        data = remote_runtimes[pylon_id]
        if time.time() - data.get("timestamp", 0) > 60:
            continue
        for plugin in data.get("runtime_info", []):
            name = plugin.get("name", "")
            if name in _PRIORITY_PLUGINS and name not in seen:
                seen[name] = plugin.get("local_version", "") or ""
    return [
        {"name": name, "version": seen[name]}
        for name in _PRIORITY_PLUGINS
        if name in seen
    ]


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=R0903
    """ API """

    @register_openapi(
        name="Get System Info (Admin)",
        description="Get version info for priority plugins across all active pylons.",
    )
    @auth.decorators.check_api(["runtime.plugins"])
    def get(self):
        """ Process GET """
        return {
            "plugins": _collect_plugin_versions(self.module.remote_runtimes),
        }


class PromptLibAPI(api_tools.APIModeHandler):  # pylint: disable=R0903
    """ API — accessible by any authenticated user (prompt_lib mode) """

    @register_openapi(
        name="Get System Info",
        description="Get version info for priority plugins (accessible to all authenticated users).",
    )
    def get(self):
        """ Process GET """
        return {
            "plugins": _collect_plugin_versions(self.module.remote_runtimes),
        }


class API(api_tools.APIBase):  # pylint: disable=R0903
    """ API """

    url_params = [
        "<string:mode>",
    ]

    mode_handlers = {
        "administration": AdminAPI,
        "prompt_lib": PromptLibAPI,
    }
