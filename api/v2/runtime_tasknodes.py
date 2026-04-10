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

from tools import auth  # pylint: disable=E0401
from tools import api_tools  # pylint: disable=E0401


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=R0903
    """ API """

    @auth.decorators.check_api(["runtime.plugins"])
    def get(self):  # pylint: disable=R0911,R0912
        """ Process GET """
        action = flask.request.args.get("action", "list")
        node = flask.request.args.get("node", None)
        scope = flask.request.args.get("scope", None)
        #
        module_manager = self.module.context.module_manager
        #
        # list
        #
        if action == "list":
            result = []
            #
            if node is not None and scope is not None:
                plugin_name, task_node_name = node.split(".", 1)
                #
                if plugin_name in module_manager.modules:
                    plugin = module_manager.modules[plugin_name].module
                    task_node = getattr(plugin, task_node_name, None)
                    #
                    if task_node is not None:
                        if scope == "pool":
                            with task_node.lock:
                                for state in task_node.global_pool_state.values():
                                    for node in state.values():
                                        result.append({
                                            "pool": node.get("pool", None),
                                            "ident": node.get("ident", None),
                                            "task_limit": node.get("task_limit", None),
                                            "running_tasks": node.get("running_tasks", None),
                                        })
                        #
                        if scope == "task":
                            with task_node.lock:
                                for state in task_node.global_task_state.values():
                                    meta = state.get("meta", None)
                                    if meta is not None:
                                        meta = str(meta)
                                    #
                                    status = state.get("status", None)
                                    if status == "stopped":
                                        continue
                                    #
                                    result.append({
                                        "task_id": state.get("task_id", None),
                                        "requestor": state.get("requestor", None),
                                        "runner": state.get("runner", None),
                                        "status": status,
                                        "meta": meta,
                                        "node": node,
                                    })
            #
            return {
                "total": len(result),
                "rows": result,
            }
        #
        # refresh
        #
        if action == "refresh":
            if node is None or scope is None:
                return {
                    "ok": False,
                    "error": "node or scope not set",
                }
            #
            plugin_name, task_node_name = node.split(".", 1)
            #
            if plugin_name not in module_manager.modules:
                return {
                    "ok": False,
                    "error": "unknown plugin",
                }
            #
            plugin = module_manager.modules[plugin_name].module
            task_node = getattr(plugin, task_node_name, None)
            #
            if task_node is None:
                return {
                    "ok": False,
                    "error": "unknown node",
                }
            #
            if scope == "pool":
                task_node.query_pool_state()
            elif scope == "task":
                task_node.query_task_state()
            else:
                return {
                    "ok": False,
                    "error": "unknown scope",
                }
            #
            return {
                "ok": True,
            }
        #
        # stop
        #
        if action == "stop":
            if node is None or scope is None:
                return {
                    "ok": False,
                    "error": "node or scope not set",
                }
            #
            plugin_name, task_node_name = node.split(".", 1)
            #
            if plugin_name not in module_manager.modules:
                return {
                    "ok": False,
                    "error": "unknown plugin",
                }
            #
            plugin = module_manager.modules[plugin_name].module
            task_node = getattr(plugin, task_node_name, None)
            #
            if task_node is None:
                return {
                    "ok": False,
                    "error": "unknown node",
                }
            #
            task_node.stop_task(scope)
            #
            return {
                "ok": True,
            }
        #
        return {
            "ok": False,
            "error": "unknown action",
        }


class API(api_tools.APIBase):  # pylint: disable=R0903
    """ API """

    url_params = [
        "<string:mode>",
    ]

    mode_handlers = {
        'administration': AdminAPI,
    }
