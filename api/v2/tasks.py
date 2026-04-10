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

import datetime

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
        scope = flask.request.args.get("scope", None)
        #
        module_manager = self.module.context.module_manager
        #
        node = "admin.task_node"
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
                        if scope == "task":
                            with task_node.lock:
                                for state in task_node.global_task_state.values():
                                    task_id = state.get("task_id", None)
                                    meta = state.get("meta", None)
                                    #
                                    # Extract user from meta dict
                                    #
                                    user = None
                                    if isinstance(meta, dict):
                                        user = meta.get("user")
                                    #
                                    if meta is not None:
                                        meta = str(meta)
                                    #
                                    status = state.get("status", None)
                                    #
                                    # Get timestamp from state_events
                                    #
                                    started_at = None
                                    event_data = task_node.state_events.get(
                                        task_id
                                    )
                                    if event_data and "timestamp" in event_data:
                                        ts = event_data["timestamp"]
                                        if isinstance(ts, datetime.datetime):
                                            started_at = ts.isoformat()
                                    #
                                    result.append({
                                        "task_id": task_id,
                                        "requestor": state.get("requestor", None),
                                        "runner": state.get("runner", None),
                                        "status": status,
                                        "meta": meta,
                                        "node": node,
                                        "started_at": started_at,
                                        "user": user,
                                    })
            #
            return {
                "total": len(result),
                "rows": result,
            }
        #
        # start
        #
        if action == "start":
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
            task_name, task_param = scope.split(":", 1)
            #
            try:
                user_id = flask.g.auth.id
            except Exception:  # pylint: disable=W0702
                user_id = None
            #
            # Resolve user email for audit trail
            #
            user_email = None
            if user_id and user_id != "-":
                try:
                    user_data = self.module.context.rpc_manager.call.auth_get_user(
                        user_id,
                    )
                    if user_data:
                        user_email = user_data.get("email")
                except Exception:  # pylint: disable=W0703
                    pass
            #
            task_id = task_node.start_task(
                task_name,
                kwargs={
                    "param": task_param,
                    "_user_id": user_id,
                },
                pool="admin",
                meta={
                    "task": task_name,
                    "user": user_email,
                },
            )
            #
            if task_id is None:
                return {
                    "ok": False,
                    "error": "unknown task",
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
        # logs
        #
        if action == "logs":
            if scope is None:
                return {
                    "ok": False,
                    "error": "scope (task_id) not set",
                }
            #
            room_key = f"room:tasknode_task:id:{scope}"
            lines = []
            #
            if "logging_hub" in module_manager.modules:
                logging_hub = module_manager.modules["logging_hub"].module
                cached = logging_hub.room_cache.get(room_key, [])
                for record in cached:
                    line = record.get("line", "")
                    if line:
                        lines.append(line)
            #
            return {
                "ok": True,
                "lines": lines,
            }
        #
        # names
        #
        if action == "names":
            return {
                "ok": True,
                "names": self.module.present_admin_tasks(),
                "tasks": self.module.present_admin_tasks_with_descriptions(),
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
