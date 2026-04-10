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

import io
import json
import time
import zipfile

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
            runtime_info = data["runtime_info"]
            #
            for plugin in sorted(runtime_info, key=lambda x: x["name"]):
                item = plugin.copy()
                #
                item["pylon_id"] = pylon_id
                #
                item.pop("config", None)
                item.pop("config_data", None)
                #
                if "git_head" in item.get("metadata", {}):
                    item_version = item.get("local_version", "-")
                    item_git_head = item["metadata"]["git_head"][:7]
                    item["local_version"] = f"{item_version} ({item_git_head})"
                #
                result.append(item)
        #
        return {
            "total": len(result),
            "rows": result,
        }

    @auth.decorators.check_api(["runtime.plugins"])
    def post(self):  # pylint: disable=R0912,R0915,R0914
        """ Process POST """
        #
        # Special: config export
        #
        if "action" in flask.request.form:
            action = flask.request.form["action"]
            #
            if action == "export_configs":
                data = json.loads(flask.request.form.get("data", "[]"))
                #
                # ---
                #
                targets = {}
                #
                for item in data:
                    pylon_id = item.get("pylon_id", "")
                    #
                    if not pylon_id:
                        continue
                    #
                    if pylon_id not in targets:
                        targets[pylon_id] = []
                    #
                    plugin_state = item.get("state", False)
                    plugin_name = item.get("name", "")
                    #
                    if not plugin_state or not plugin_name:
                        continue
                    #
                    if plugin_name not in targets[pylon_id]:
                        targets[pylon_id].append(plugin_name)
                #
                # ---
                #
                file_obj = io.BytesIO()
                #
                with zipfile.ZipFile(file_obj, mode="w", compression=zipfile.ZIP_DEFLATED) as zfile:
                    for pylon_id in list(sorted(self.module.remote_runtimes.keys())):
                        if pylon_id not in targets:
                            continue
                        #
                        data = self.module.remote_runtimes[pylon_id]
                        #
                        try:
                            pylon_settings = data["pylon_settings"]["tunable"]
                            #
                            if pylon_settings:
                                zfile.writestr(f"{pylon_id}/pylon.yml", pylon_settings)
                        except:  # pylint: disable=W0702
                            pass
                        #
                        runtime_info = data["runtime_info"]
                        for plugin in sorted(runtime_info, key=lambda x: x["name"]):
                            plugin_name = plugin["name"]
                            #
                            if plugin_name not in targets[pylon_id]:
                                continue
                            #
                            config_data = plugin.get("config_data", "")
                            #
                            if not config_data:
                                continue
                            #
                            zfile.writestr(f"{pylon_id}/{plugin_name}.yml", config_data)
                #
                file_obj.seek(0)
                #
                # ---
                #
                return flask.send_file(
                    file_obj,
                    mimetype="application/zip",
                    as_attachment=True,
                    download_name=f"config_export_{int(time.time())}.zip",
                )
            #
            if action == "import_configs":
                if "file" in flask.request.files:
                    file_data = flask.request.files["file"]
                    #
                    log.info("Importing config from: %s", file_data.filename)
                    #
                    zip_data = io.BytesIO(file_data.stream.read())
                    target_events = {}
                    #
                    with zipfile.ZipFile(zip_data) as zfile:
                        for item in zfile.namelist():
                            if "/" not in item:
                                continue
                            #
                            pylon_id, name = item.split("/", 1)
                            #
                            if pylon_id not in target_events:
                                target_events[pylon_id] = {
                                    "pylon_id": pylon_id,
                                    "configs": {},
                                    "actions": [],
                                    "restart": False,
                                }
                            #
                            if not name.endswith(".yml"):
                                continue
                            #
                            base_name = name.rsplit(".", 1)[0]
                            #
                            with zfile.open(item) as ifile:
                                base_data = ifile.read().decode()
                            #
                            if base_name == "pylon":
                                target_events[pylon_id]["actions"].append(
                                    ["update_pylon_config", base_data]
                                )
                            else:
                                target_events[pylon_id]["configs"][base_name] = base_data
                    #
                    for event_data in target_events.values():
                        self.module.context.event_manager.fire_event(
                            "bootstrap_runtime_update",
                            event_data,
                        )
                #
                return {"ok": True}
            #
            return {"ok": False}
        #
        # Normal
        #
        data = flask.request.get_json()
        #
        if "data" not in data or not data["data"]:
            return {"ok": True}
        #
        action = data.get("action", "update")
        #
        # Collect targets
        #
        targets = {}
        #
        for item in data["data"]:
            pylon_id = item.get("pylon_id", "")
            #
            if not pylon_id:
                continue
            #
            if pylon_id not in targets:
                targets[pylon_id] = []
            #
            plugin_state = item.get("state", False)
            plugin_name = item.get("name", "")
            #
            if not plugin_state or not plugin_name:
                continue
            #
            if plugin_name not in targets[pylon_id]:
                targets[pylon_id].append(plugin_name)
        #
        events = []
        #
        for pylon_id, plugins in targets.items():
            if not plugins:
                continue
            #
            if action == "update":
                log.info("Requesting plugin update(s): %s -> %s", pylon_id, plugins)
                #
                event_data = {
                    "pylon_id": pylon_id,
                    "plugins": plugins,
                    "restart": True,
                    "pylon_pid": 1,
                }
                #
                if pylon_id == self.module.context.id:
                    events.append(event_data)
                else:
                    events.insert(0, event_data)
            #
            elif action == "update_with_reqs":
                log.info("Requesting plugin update(s)+req(s): %s -> %s", pylon_id, plugins)
                #
                event_data = {
                    "pylon_id": pylon_id,
                    "plugins": plugins,
                    "actions": [
                        ["delete_requirements", plugins],
                    ],
                    "restart": True,
                    "pylon_pid": 1,
                }
                #
                if pylon_id == self.module.context.id:
                    events.append(event_data)
                else:
                    events.insert(0, event_data)
            #
            elif action == "purge_reqs":
                log.info("Requesting reqs purge(s): %s -> %s", pylon_id, plugins)
                #
                event_data = {
                    "pylon_id": pylon_id,
                    "actions": [
                        ["delete_requirements", plugins],
                    ],
                    "restart": True,
                    "pylon_pid": 1,
                }
                #
                if pylon_id == self.module.context.id:
                    events.append(event_data)
                else:
                    events.insert(0, event_data)
            #
            elif action == "delete":
                log.info("Requesting plugin delete(s): %s -> %s", pylon_id, plugins)
                #
                plugins_del = [f"!{plugin}" for plugin in plugins]
                #
                event_data = {
                    "pylon_id": pylon_id,
                    "plugins": plugins_del,
                    "restart": True,
                    "pylon_pid": 1,
                }
                #
                if pylon_id == self.module.context.id:
                    events.append(event_data)
                else:
                    events.insert(0, event_data)
            #
            elif action == "reload":
                log.info("Requesting plugin reload(s): %s -> %s", pylon_id, plugins)
                #
                event_data = {
                    "pylon_id": pylon_id,
                    "reload": plugins,
                    "restart": False,
                }
                #
                if pylon_id == self.module.context.id:
                    events.append(event_data)
                else:
                    events.insert(0, event_data)
        #
        # Emit events
        #
        for event_item in events:
            self.module.context.event_manager.fire_event(
                "bootstrap_runtime_update",
                event_item,
            )
        #
        return {"ok": True}


class API(api_tools.APIBase):  # pylint: disable=R0903
    """ API """

    url_params = [
        "<string:mode>",
    ]

    mode_handlers = {
        'administration': AdminAPI,
    }
