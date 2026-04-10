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

""" Event """

import time

from pylon.core.tools import log, web  # pylint: disable=E0611,E0401,W0611


class Event:  # pylint: disable=R0903,E1101
    """ Event """

    @web.event("bootstrap_runtime_info")
    def _bootstrap_runtime_info(self, context, event, payload):  # pylint: disable=R0914
        _ = context, event
        #
        if not isinstance(payload, dict):
            return
        #
        pylon_id = payload.get("pylon_id", "")
        #
        if not pylon_id:
            return
        #
        data = payload.copy()
        data["timestamp"] = time.time()
        self.remote_runtimes[pylon_id] = data

    @web.event("bootstrap_runtime_info_prune")
    def _bootstrap_runtime_info_prune(self, context, event, payload):  # pylint: disable=R0914
        _ = context, event
        #
        if not isinstance(payload, dict):
            return
        #
        pylon_id = payload.get("pylon_id", "")
        #
        if not pylon_id:
            return
        #
        self.remote_runtimes.pop(pylon_id, None)
