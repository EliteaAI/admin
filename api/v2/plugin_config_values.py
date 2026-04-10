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
import copy

import flask  # pylint: disable=E0401
import yaml  # pylint: disable=E0401

from pylon.core.tools import log  # pylint: disable=E0611,E0401

from tools import auth  # pylint: disable=E0401
from tools import api_tools  # pylint: disable=E0401

def get_nested(d, path):
    """ Get a value from a nested dict using dot-notation path """
    keys = path.split(".")
    for key in keys:
        if isinstance(d, dict):
            d = d.get(key)
        else:
            return None
    return d


def set_nested(d, path, value):
    """ Set a value in a nested dict using dot-notation path """
    keys = path.split(".")
    for key in keys[:-1]:
        if key not in d or not isinstance(d[key], dict):
            d[key] = {}
        d = d[key]
    d[keys[-1]] = value


def find_pylon_id_by_prefix(remote_runtimes, pylon_prefix):
    """ Find actual pylon_id that contains the given prefix """
    normalized_prefix = pylon_prefix.replace("-", "_").replace(" ", "_").lower()
    for pylon_id in remote_runtimes:
        normalized_id = pylon_id.replace("-", "_").replace(" ", "_").lower()
        if normalized_prefix in normalized_id:
            return pylon_id
    return None


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=R0903
    """ API """

    @auth.decorators.check_api(["runtime.plugins"])
    def get(self, section_id):
        """ Read current values for all fields in the given section """
        #
        # Pass 1: collect all entries
        raw_entries = []
        #
        for pylon_id in list(sorted(self.module.remote_runtimes.keys())):
            data = self.module.remote_runtimes[pylon_id]
            #
            if time.time() - data.get("timestamp", 0) > 60:
                continue
            #
            runtime_info = data.get("runtime_info", [])
            #
            for plugin in runtime_info:
                schema = plugin.get("admin_schema")
                if not schema:
                    continue
                #
                plugin_name = plugin["name"]
                config = plugin.get("config") or {}
                #
                for prop_key, prop_def in schema.get("properties", {}).items():
                    if prop_def.get("section") != section_id:
                        continue
                    #
                    path = prop_def.get("path", prop_key)
                    raw_value = get_nested(config, path)
                    if raw_value is None:
                        raw_value = prop_def.get("default")
                    #
                    raw_entries.append({
                        "prop_key": prop_key,
                        "pylon_id": pylon_id,
                        "plugin_name": plugin_name,
                        "raw_value": raw_value,
                        "path": path,
                        "requires_restart": prop_def.get("requires_restart", False),
                    })
        #
        # Pass 2: detect multi-pylon keys
        key_pylons = {}
        for entry in raw_entries:
            pk = entry["prop_key"]
            if pk not in key_pylons:
                key_pylons[pk] = set()
            key_pylons[pk].add(entry["pylon_id"])
        #
        # Pass 3: build values with unique keys
        values = {}
        fields_meta = {}
        #
        for entry in raw_entries:
            pk = entry["prop_key"]
            if len(key_pylons.get(pk, set())) > 1:
                unique_key = f"{pk}::{entry['pylon_id']}"
            else:
                unique_key = pk
            #
            values[unique_key] = entry["raw_value"]
            fields_meta[unique_key] = {
                "plugin": entry["plugin_name"],
                "pylon_id": entry["pylon_id"],
                "path": entry["path"],
                "requires_restart": entry["requires_restart"],
            }
        #
        return {"values": values, "fields_meta": fields_meta}

    @auth.decorators.check_api(["runtime.plugins"])
    def put(self, section_id):
        """ Update values for fields in the given section """
        request_data = flask.request.get_json()
        if not request_data:
            return {"error": "No data provided"}, 400
        #
        new_values = request_data.get("values", {})
        if not new_values:
            return {"saved": True, "requires_restart": []}
        #
        # Pre-parse incoming keys (may contain ::pylon_id suffix)
        parsed_values = {}  # (prop_key, pylon_id_or_None) -> value
        for key, value in new_values.items():
            if "::" in key:
                prop_key, target_pylon = key.split("::", 1)
                parsed_values[(prop_key, target_pylon)] = value
            else:
                parsed_values[(key, None)] = value
        #
        # Collect changes grouped by (pylon_id, plugin_name)
        targets = {}  # (pylon_id, plugin_name) -> [(path, value), ...]
        reload_needed = {}  # pylon_id -> set(plugin_names)
        #
        for pylon_id in list(sorted(self.module.remote_runtimes.keys())):
            data = self.module.remote_runtimes[pylon_id]
            #
            if time.time() - data.get("timestamp", 0) > 60:
                continue
            #
            runtime_info = data.get("runtime_info", [])
            #
            for plugin in runtime_info:
                schema = plugin.get("admin_schema")
                if not schema:
                    continue
                #
                plugin_name = plugin["name"]
                #
                config = plugin.get("config") or {}
                #
                for prop_key, prop_def in schema.get("properties", {}).items():
                    if prop_def.get("section") != section_id:
                        continue
                    #
                    # Match: pylon-specific key first, then generic key
                    if (prop_key, pylon_id) in parsed_values:
                        value = parsed_values[(prop_key, pylon_id)]
                    elif (prop_key, None) in parsed_values:
                        value = parsed_values[(prop_key, None)]
                    else:
                        continue
                    #
                    path = prop_def.get("path", prop_key)
                    #
                    # Skip if value hasn't changed
                    current_value = get_nested(config, path)
                    if current_value is None:
                        current_value = prop_def.get("default")
                    if value == current_value:
                        continue
                    #
                    target_key = (pylon_id, plugin_name)
                    if target_key not in targets:
                        targets[target_key] = []
                    targets[target_key].append((path, value))
                    #
                    if prop_def.get("requires_restart", False):
                        if pylon_id not in reload_needed:
                            reload_needed[pylon_id] = set()
                        reload_needed[pylon_id].add(plugin_name)
                    #
                    # Handle sync_targets
                    for sync in prop_def.get("sync_targets", []):
                        sync_pylon_prefix = sync.get("pylon", "")
                        sync_plugin = sync.get("plugin", "")
                        sync_path = sync.get("path", path)
                        #
                        sync_pylon_id = find_pylon_id_by_prefix(
                            self.module.remote_runtimes, sync_pylon_prefix,
                        )
                        if not sync_pylon_id:
                            log.warning(
                                "Sync target pylon not found: %s", sync_pylon_prefix,
                            )
                            continue
                        #
                        st_key = (sync_pylon_id, sync_plugin)
                        if st_key not in targets:
                            targets[st_key] = []
                        targets[st_key].append((sync_path, value))
                        #
                        if prop_def.get("requires_restart", False):
                            if sync_pylon_id not in reload_needed:
                                reload_needed[sync_pylon_id] = set()
                            reload_needed[sync_pylon_id].add(sync_plugin)
        #
        # For each target, patch YAML and fire event
        for (pylon_id, plugin_name), changes in targets.items():
            # Find current config_data for this plugin
            config_data = ""
            rt_data = self.module.remote_runtimes.get(pylon_id, {})
            for plugin in rt_data.get("runtime_info", []):
                if plugin["name"] == plugin_name:
                    config_data = plugin.get("config_data", "")
                    break
            #
            config_dict = yaml.safe_load(config_data) or {}
            #
            for path, value in changes:
                set_nested(config_dict, path, value)
            #
            new_yaml = yaml.dump(config_dict, default_flow_style=False, allow_unicode=True)
            #
            log.info("Plugin config update: %s -> %s", pylon_id, plugin_name)
            self.module.context.event_manager.fire_event(
                "bootstrap_runtime_update",
                {
                    "pylon_id": pylon_id,
                    "configs": {
                        plugin_name: new_yaml,
                    },
                    "restart": False,
                },
            )
            #
            # Update local cache so subsequent GETs return new values immediately
            plugin["config"] = config_dict
            plugin["config_data"] = new_yaml
        #
        return {
            "saved": True,
            "requires_restart": [
                {"pylon_id": pid, "plugins": list(plugins)}
                for pid, plugins in reload_needed.items()
            ],
        }

class API(api_tools.APIBase):  # pylint: disable=R0903
    """ API """

    url_params = [
        "<string:mode>/<string:section_id>",
    ]

    mode_handlers = {
        'administration': AdminAPI,
    }
