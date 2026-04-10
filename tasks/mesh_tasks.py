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

from .logs import make_logger


def mesh_get_plugin_frozen_requirements(*_args, **kwargs):
    """Get frozen pip requirements for a plugin via mesh. Param: 'pylon_id:plugin_name'."""
    #
    with make_logger() as log:
        log.info("Starting")
        start_ts = time.time()
        #
        try:
            if "param" not in kwargs:
                raise ValueError("Param is not set")
            #
            pylon_id, plugin_name = kwargs["param"].rsplit(":", 1)
            #
            from tools import this  # pylint: disable=E0401,C0415
            #
            bootstrap = this.for_module("bootstrap").module
            mesh_service_node = getattr(bootstrap, "mesh_service_node", None)
            #
            if mesh_service_node is None:
                raise ValueError("Mesh is not enabled or present")
            #
            result = mesh_service_node.request(
                service=f"mesh:service:{pylon_id}:get_plugin_frozen_requirements",
                kwargs={
                    "plugin_name": plugin_name,
                },
            )
            #
            log.info("Result:\n%s", result)
        except:  # pylint: disable=W0702
            log.exception("Got exception, stopping")
        #
        end_ts = time.time()
        log.info("Exiting (duration = %s)", end_ts - start_ts)
