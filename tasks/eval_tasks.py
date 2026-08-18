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

""" Task """

import time

from tools import context  # pylint: disable=E0401

from .logs import make_logger


def resync_platform_dimensions(*args, **kwargs):
    """Push every platform eval dimension's definition to the projects using it. No params.

    The bulk equivalent of the per-dimension Sync button in the admin console. Update-only: a
    project that never attached a dimension does not get a copy from this.
    """
    #
    with make_logger() as log:
        log.info("Starting")
        start_ts = time.time()
        #
        try:
            result = context.rpc_manager.timeout(600).elitea_core_platform_dimension_resync()
            #
            log.info("Synced %s project(s)", len(result.get("synced", [])))
            for failure in result.get("failures", []):
                log.error(
                    "Project %s failed: %s", failure.get("project_id"), failure.get("error"),
                )
        except:  # pylint: disable=W0702
            log.exception("Got exception, stopping")
        #
        log.info("Exiting (duration = %s)", time.time() - start_ts)
