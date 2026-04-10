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

import flask  # pylint: disable=E0401,W0611

from pylon.core.tools import log  # pylint: disable=E0611,E0401,W0611

from tools import auth  # pylint: disable=E0401
from tools import api_tools  # pylint: disable=E0401


SECTION_DEFINITIONS = {
    "guardrails": {
        "title": "Guardrails",
        "order": 1,
        "icon": "security",
        "description": "Control platform-wide security policies, toolkit restrictions, and MCP exposure settings.",
    },
    "mcp_servers": {
        "title": "MCP Servers",
        "order": 2,
        "icon": "dns",
        "description": "Configure Model Context Protocol server definitions available to the indexer runtime.",
    },
    "observability": {
        "title": "Observability",
        "order": 3,
        "icon": "monitoring",
        "description": "Manage distributed tracing and audit trail settings across all pylons.",
    },
    "litellm": {
        "title": "LiteLLM",
        "order": 4,
        "icon": "model_training",
        "description": "Configure the LiteLLM proxy — connection mode, credentials, and model access policies.",
    },
    "runtime": {
        "title": "Runtime",
        "order": 5,
        "icon": "settings",
        "description": "Configure indexer worker runtime behavior, task processing, and development settings.",
    },
    "admin_panel": {
        "title": "Admin Panel",
        "order": 6,
        "icon": "admin_panel_settings",
        "description": "Manage admin panel plugin availability and reload capabilities.",
    },
    "auth": {
        "title": "Authentication",
        "order": 7,
        "icon": "lock",
        "description": "Configure the authentication provider and identity settings.",
    },
     "dedicated_banner": {
        "title": "Banner",
        "order": 89,
        "icon": "campaign",
        "description": "Enable dedicated banner to communicate important notifications across the platform.",
        "always_visible": True,
    },
    "maintenance": {
        "title": "Maintenance",
        "order": 90,
        "icon": "construction",
        "description": "Enable maintenance mode to show a splash screen to all non-admin users.",
        "always_visible": True,
    },
    "advanced": {
        "title": "Advanced",
        "order": 100,
        "icon": "code",
        "description": "View and edit raw plugin configurations for all connected pylons.",
        "always_visible": True,
    },
}


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=R0903
    """ API """

    @auth.decorators.check_api(["runtime.plugins"])
    def get(self):
        """ Collect admin_schema from all plugins across all active pylons """
        sections = {}
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
                for prop_key, prop_def in schema.get("properties", {}).items():
                    section_id = prop_def.get("section", "runtime")
                    #
                    if section_id not in sections:
                        sec_meta = SECTION_DEFINITIONS.get(section_id, {})
                        sections[section_id] = {
                            "id": section_id,
                            "title": sec_meta.get("title", section_id.replace("_", " ").title()),
                            "description": sec_meta.get("description", ""),
                            "order": sec_meta.get("order", 99),
                            "icon": sec_meta.get("icon", "settings"),
                            "fields": [],
                        }
                    #
                    # Skip fields that are sync targets (owned by another plugin)
                    if prop_def.get("_is_sync_target"):
                        continue
                    #
                    field_entry = dict(prop_def)
                    field_entry["key"] = prop_key
                    field_entry["plugin"] = plugin_name
                    field_entry["pylon_id"] = pylon_id
                    sections[section_id]["fields"].append(field_entry)
        #
        # Ensure always-visible sections are included
        for sec_id, sec_meta in SECTION_DEFINITIONS.items():
            if sec_meta.get("always_visible") and sec_id not in sections:
                sections[sec_id] = {
                    "id": sec_id,
                    "title": sec_meta.get("title", sec_id.replace("_", " ").title()),
                    "description": sec_meta.get("description", ""),
                    "order": sec_meta.get("order", 99),
                    "icon": sec_meta.get("icon", "settings"),
                    "fields": [],
                }
        #
        # Disambiguate duplicate prop_keys across pylons
        for section in sections.values():
            key_pylons = {}
            for field in section["fields"]:
                pk = field["key"]
                if pk not in key_pylons:
                    key_pylons[pk] = set()
                key_pylons[pk].add(field["pylon_id"])
            #
            for field in section["fields"]:
                if len(key_pylons.get(field["key"], set())) > 1:
                    field["_original_key"] = field["key"]
                    field["key"] = f"{field['key']}::{field['pylon_id']}"
        #
        result = sorted(sections.values(), key=lambda s: s["order"])
        return {"sections": result}


class API(api_tools.APIBase):  # pylint: disable=R0903
    """ API """

    url_params = [
        "<string:mode>",
    ]

    mode_handlers = {
        'administration': AdminAPI,
    }
