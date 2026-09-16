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

""" Custom Theme API - Platform branding and custom color palette management """

import os
import glob
import time

import flask
import yaml

from pylon.core.tools import log

from tools import auth
from tools import api_tools, register_openapi


# Constants
CUSTOM_THEME_CONFIG_PATH = "extra_ui_config.custom_theme"


def get_nested(d, path):
    """Get a value from a nested dict using dot-notation path"""
    keys = path.split(".")
    for key in keys:
        if isinstance(d, dict):
            d = d.get(key)
        else:
            return None
    return d


def set_nested(d, path, value):
    """Set a value in a nested dict using dot-notation path"""
    keys = path.split(".")
    for key in keys[:-1]:
        if key not in d or not isinstance(d[key], dict):
            d[key] = {}
        d = d[key]
    d[keys[-1]] = value


def delete_nested(d, path):
    """Delete a value from a nested dict using dot-notation path"""
    keys = path.split(".")
    for key in keys[:-1]:
        if isinstance(d, dict) and key in d:
            d = d[key]
        else:
            return False
    if isinstance(d, dict) and keys[-1] in d:
        del d[keys[-1]]
        return True
    return False


def get_elitea_core_config(remote_runtimes):
    """Get elitea_core plugin config from remote runtimes"""
    for pylon_id in remote_runtimes:
        data = remote_runtimes[pylon_id]
        if time.time() - data.get("timestamp", 0) > 60:
            continue
        for plugin in data.get("runtime_info", []):
            if plugin["name"] == "elitea_core":
                return {
                    "pylon_id": pylon_id,
                    "config": plugin.get("config") or {},
                    "config_data": plugin.get("config_data", ""),
                    "plugin": plugin,
                }
    return None


def get_custom_theme_data(remote_runtimes):
    """Extract custom theme data from elitea_core config"""
    core_config = get_elitea_core_config(remote_runtimes)
    if not core_config:
        return None

    custom_theme = get_nested(core_config["config"], CUSTOM_THEME_CONFIG_PATH)
    if not custom_theme:
        return None

    return {
        "enabled": custom_theme.get("enabled", False),
        "mode": custom_theme.get("mode", "dark"),
        "palette": custom_theme.get("palette"),
        "logo_url": custom_theme.get("logo_url"),
    }


def update_custom_theme_config(module, theme_data):
    """Update custom theme in elitea_core config via bootstrap_runtime_update event"""
    core_config = get_elitea_core_config(module.remote_runtimes)
    if not core_config:
        raise RuntimeError("elitea_core plugin not found in remote runtimes")

    config_dict = yaml.safe_load(core_config["config_data"]) or {}
    set_nested(config_dict, CUSTOM_THEME_CONFIG_PATH, theme_data)

    new_yaml = yaml.dump(config_dict, default_flow_style=False, allow_unicode=True)

    log.info("Updating custom theme config in elitea_core")
    module.context.event_manager.fire_event(
        "bootstrap_runtime_update",
        {
            "pylon_id": core_config["pylon_id"],
            "configs": {
                "elitea_core": new_yaml,
            },
            "restart": False,
        },
    )

    # Update local cache
    core_config["plugin"]["config"] = config_dict
    core_config["plugin"]["config_data"] = new_yaml


def delete_custom_theme_config(module):
    """Delete custom theme from elitea_core config"""
    core_config = get_elitea_core_config(module.remote_runtimes)
    if not core_config:
        raise RuntimeError("elitea_core plugin not found in remote runtimes")

    config_dict = yaml.safe_load(core_config["config_data"]) or {}
    deleted = delete_nested(config_dict, CUSTOM_THEME_CONFIG_PATH)

    if not deleted:
        return False

    new_yaml = yaml.dump(config_dict, default_flow_style=False, allow_unicode=True)

    log.info("Deleting custom theme config from elitea_core")
    module.context.event_manager.fire_event(
        "bootstrap_runtime_update",
        {
            "pylon_id": core_config["pylon_id"],
            "configs": {
                "elitea_core": new_yaml,
            },
            "restart": False,
        },
    )

    # Update local cache
    core_config["plugin"]["config"] = config_dict
    core_config["plugin"]["config_data"] = new_yaml
    return True


class AdminAPI(api_tools.APIModeHandler):
    """Admin API for custom theme CRUD operations"""

    @register_openapi(
        name="Get Custom Theme (Admin)",
        description="Get the current custom theme configuration with full metadata.",
    )
    @auth.decorators.check_api(["runtime.plugins"])
    def get(self):
        """Get current custom theme configuration"""
        theme_data = get_custom_theme_data(self.module.remote_runtimes)

        if not theme_data:
            return {
                "exists": False,
                "theme": None,
            }

        # logo_url in theme_data is the public static URL (/app/platform_logo/...)
        # which works for both preview and storage
        return {
            "exists": True,
            "theme": theme_data,
        }

    @register_openapi(
        name="Save Custom Theme",
        description="Create or update the custom theme configuration.",
    )
    @auth.decorators.check_api(["runtime.plugins"])
    def put(self):
        """Create or update custom theme"""
        request_data = flask.request.get_json()
        if not request_data:
            return {"error": "No data provided"}, 400

        # Get palette (optional - can have just logo without custom colors)
        palette = request_data.get("palette")

        mode = request_data.get("mode", "dark")
        if mode not in ("dark", "light"):
            return {"error": "mode must be 'dark' or 'light'"}, 400

        # Get existing theme to preserve logo_url if not provided
        existing_theme = get_custom_theme_data(self.module.remote_runtimes)
        logo_url = request_data.get("logo_url")
        if logo_url is None and existing_theme:
            logo_url = existing_theme.get("logo_url")

        theme_data = {
            "enabled": True,
            "mode": mode,
            "palette": palette,
            "logo_url": logo_url,
        }

        try:
            update_custom_theme_config(self.module, theme_data)
        except RuntimeError as e:
            return {"error": str(e)}, 500

        return {
            "saved": True,
            "theme": theme_data,
        }

    @register_openapi(
        name="Delete Custom Theme",
        description="Delete the entire custom theme configuration.",
    )
    @auth.decorators.check_api(["runtime.plugins"])
    def delete(self):
        """Delete custom theme"""
        # First, try to delete the logo file if it exists
        theme_data = get_custom_theme_data(self.module.remote_runtimes)
        if theme_data and theme_data.get("logo_url"):
            try:
                self._delete_logo_file(theme_data["logo_url"])
            except Exception as e:
                log.warning("Failed to delete logo file: %s", e)

        try:
            deleted = delete_custom_theme_config(self.module)
        except RuntimeError as e:
            return {"error": str(e)}, 500

        if not deleted:
            return {"deleted": False, "message": "No custom theme exists"}

        return {"deleted": True}

    def _get_elitea_core_module(self):
        """Get elitea_core module instance"""
        modules = self.module.context.module_manager.modules
        descriptor = modules.get("elitea_core")
        if descriptor is None:
            return None
        return descriptor.module

    def _delete_logo_file(self, logo_url):
        """Delete logo file from static directory"""
        if not logo_url:
            return

        try:
            # Get elitea_core module for platform_logo_path
            elitea_core = self._get_elitea_core_module()
            if not elitea_core:
                log.warning("Could not get elitea_core module for logo deletion")
                return

            if not hasattr(elitea_core, "platform_logo_path"):
                log.warning("elitea_core module has no platform_logo_path attribute")
                return

            logo_dir = elitea_core.platform_logo_path
            log.info("Deleting logo files from: %s", logo_dir)

            # Delete all logo files
            pattern = str(logo_dir / "logo.*")
            files_to_delete = glob.glob(pattern)
            log.info("Found logo files to delete: %s", files_to_delete)

            for old_file in files_to_delete:
                try:
                    os.remove(old_file)
                    log.info("Deleted logo file: %s", old_file)
                except Exception as e:
                    log.warning("Failed to delete logo file %s: %s", old_file, e)
        except Exception as e:
            log.error("Failed to delete logo file: %s", e)


class PromptLibAPI(api_tools.APIModeHandler):
    """Public API for fetching custom theme (used by main UI)"""

    @register_openapi(
        name="Get Custom Theme (Public)",
        description="Get the custom theme palette and logo for the main UI.",
    )
    def get(self):
        """Get custom theme for public consumption"""
        theme_data = get_custom_theme_data(self.module.remote_runtimes)

        if not theme_data or not theme_data.get("enabled"):
            return {
                "palette": None,
                "logo_url": None,
            }

        # Return the static URL directly - it's served via /app/platform_logo/
        # and doesn't require authentication
        # Include mode inside the palette (matching darkPalette.js / lightPalette.js structure)
        palette = theme_data.get("palette") or {}
        palette_with_mode = {
            "mode": theme_data.get("mode", "dark"),
            **palette,
        }
        return {
            "palette": palette_with_mode,
            "logo_url": theme_data.get("logo_url"),
        }


class API(api_tools.APIBase):
    """Custom Theme API"""

    url_params = [
        "<string:mode>",
    ]

    mode_handlers = {
        "administration": AdminAPI,
        "prompt_lib": PromptLibAPI,
    }
