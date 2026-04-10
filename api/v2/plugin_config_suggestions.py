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

import flask  # pylint: disable=E0401

from pylon.core.tools import log  # pylint: disable=E0611,E0401

from tools import auth  # pylint: disable=E0401
from tools import api_tools  # pylint: disable=E0401


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=R0903
    """ API """

    @auth.decorators.check_api(["runtime.plugins"])
    def get(self, source):
        """ Return suggestion values for admin config fields """
        #
        if source == "toolkit_names":
            return self._get_toolkit_names()
        #
        if source == "toolkit_tools":
            toolkit = flask.request.args.get("toolkit", "")
            return self._get_toolkit_tools(toolkit)
        #
        return {"error": f"Unknown source: {source}"}, 400

    def _get_elitea_core_module(self):
        """ Get elitea_core module instance """
        modules = self.module.context.module_manager.modules
        descriptor = modules.get("elitea_core")
        if descriptor is None:
            return None
        return descriptor.module

    def _get_toolkit_names(self):
        """ Get all registered toolkit type names from elitea_core """
        try:
            elitea_core = self._get_elitea_core_module()
            if not elitea_core:
                return {"values": []}
            #
            names = sorted(elitea_core.toolkit_schemas.keys())
            return {"values": names}
        except Exception as e:
            log.warning("Failed to get toolkit names: %s", e)
            return {"values": []}

    def _get_toolkit_tools(self, toolkit):
        """ Get tool names for a specific toolkit type """
        try:
            elitea_core = self._get_elitea_core_module()
            if not elitea_core:
                return {"values": []}
            #
            schema = elitea_core.toolkit_schemas.get(toolkit, {})
            #
            # Tool names live in the selected_tools property as a Literal enum.
            # In JSON Schema: properties.selected_tools.items.enum
            tools = []
            props = schema.get("properties", {})
            sel = props.get("selected_tools", {})
            #
            # Handle both JSON Schema draft formats
            items = sel.get("items", {})
            if isinstance(items, dict):
                tools = items.get("enum", [])
                # Pydantic V2 emits "const" instead of "enum" for single-value Literals
                if not tools and "const" in items:
                    tools = [items["const"]]
            #
            # Fallback: check args_schemas keys (may live directly on the
            # property or nested under json_schema_extra depending on
            # Pydantic version / toolkit implementation)
            if not tools:
                args_schemas = (
                    sel.get("args_schemas")
                    or sel.get("json_schema_extra", {}).get("args_schemas")
                )
                if isinstance(args_schemas, dict):
                    tools = list(args_schemas.keys())
            #
            return {"values": sorted(tools)}
        except Exception as e:
            log.warning("Failed to get toolkit tools: %s", e)
            return {"values": []}


class API(api_tools.APIBase):  # pylint: disable=R0903
    """ API """

    url_params = [
        "<string:mode>/<string:source>",
    ]

    mode_handlers = {
        'administration': AdminAPI,
    }
