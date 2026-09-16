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

""" Custom Theme Logo API - Logo upload and deletion using static file approach """

import os
import glob

import flask

from pylon.core.tools import log

from tools import auth
from tools import api_tools, register_openapi

from .custom_theme import (
    get_custom_theme_data,
    update_custom_theme_config,
)


class AdminAPI(api_tools.APIModeHandler):
    """Admin API for logo upload/delete/serve using static files"""

    def _get_elitea_core_module(self):
        """Get elitea_core module instance"""
        modules = self.module.context.module_manager.modules
        descriptor = modules.get("elitea_core")
        if descriptor is None:
            return None
        return descriptor.module

    @register_openapi(
        name="Get Custom Theme Logo (Admin)",
        description="Serve the custom theme logo image for admin preview.",
    )
    @auth.decorators.check_api(["runtime.plugins"])
    def get(self):
        """Serve logo image for admin preview"""
        theme_data = get_custom_theme_data(self.module.remote_runtimes)

        if not theme_data or not theme_data.get("logo_url"):
            return {"error": "No logo configured"}, 404

        logo_url = theme_data["logo_url"]

        # Extract filename from stored URL
        # URL format: /app/platform_logo/logo.{ext}
        parts = logo_url.rstrip("/").split("/")
        if len(parts) < 1:
            return {"error": "Invalid logo URL format"}, 500

        filename = parts[-1]

        # Get elitea_core module for platform_logo_path
        elitea_core = self._get_elitea_core_module()
        if not elitea_core:
            return {"error": "elitea_core module not found"}, 500

        logo_path = elitea_core.platform_logo_path / filename

        if not logo_path.exists():
            return {"error": "Logo file not found"}, 404

        try:
            # Determine content type from extension
            ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            content_types = {
                "png": "image/png",
                "svg": "image/svg+xml",
            }
            content_type = content_types.get(ext, "application/octet-stream")

            return flask.send_file(
                str(logo_path),
                mimetype=content_type,
                download_name=filename,
                as_attachment=False,
            )

        except Exception as e:
            log.error("Failed to serve logo: %s", e)
            return {"error": "Logo not found"}, 404

    @register_openapi(
        name="Upload Custom Theme Logo",
        description="Upload a logo image for the custom theme.",
    )
    @auth.decorators.check_api(["runtime.plugins"])
    def post(self):
        """Upload logo image to static directory"""
        if "file" not in flask.request.files:
            return {"error": "No file provided"}, 400

        file = flask.request.files["file"]
        if not file.filename:
            return {"error": "No file selected"}, 400

        # Validate file type (only SVG and PNG for logo)
        allowed_extensions = {"png", "svg"}
        ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
        if ext not in allowed_extensions:
            return {
                "error": "Invalid file type. Only PNG and SVG are allowed."
            }, 400

        # Read file data
        file_data = file.read()

        # Validate file size (max 5MB)
        max_size = 5 * 1024 * 1024
        if len(file_data) > max_size:
            return {"error": "File too large. Maximum size is 5MB"}, 400

        try:
            # Get elitea_core module for platform_logo_path
            elitea_core = self._get_elitea_core_module()
            if not elitea_core:
                return {"error": "elitea_core module not found"}, 500

            logo_dir = elitea_core.platform_logo_path

            # Delete any existing logo files
            for old_file in glob.glob(str(logo_dir / "logo.*")):
                try:
                    os.remove(old_file)
                except Exception as e:
                    log.warning("Failed to delete old logo file %s: %s", old_file, e)

            # Save new logo file with simple name
            filename = f"logo.{ext}"
            logo_path = logo_dir / filename

            with open(logo_path, "wb") as f:
                f.write(file_data)

            # Build static URL
            logo_url = f"/app/platform_logo/{filename}"

            # Update config with new logo URL
            theme_data = get_custom_theme_data(self.module.remote_runtimes)
            if theme_data:
                theme_data["logo_url"] = logo_url
                theme_data["enabled"] = True  # Enable theme when logo is uploaded
                update_custom_theme_config(self.module, theme_data)
            else:
                # Create minimal theme config with just logo
                theme_data = {
                    "enabled": True,  # Enable theme - user wants custom branding
                    "mode": "dark",
                    "palette": None,
                    "logo_url": logo_url,
                }
                update_custom_theme_config(self.module, theme_data)

            # Return the logo URL - same URL works for both preview and storage
            # (the /app/platform_logo/ route is public)
            return {
                "uploaded": True,
                "logo_url": logo_url,
                "filename": filename,
            }

        except Exception as e:
            log.error("Failed to upload logo: %s", e)
            return {"error": f"Upload failed: {str(e)}"}, 500

    @register_openapi(
        name="Delete Custom Theme Logo",
        description="Delete the custom theme logo.",
    )
    @auth.decorators.check_api(["runtime.plugins"])
    def delete(self):
        """Delete logo from static directory"""
        theme_data = get_custom_theme_data(self.module.remote_runtimes)

        if not theme_data or not theme_data.get("logo_url"):
            return {"deleted": False, "message": "No logo exists"}

        try:
            # Get elitea_core module for platform_logo_path
            elitea_core = self._get_elitea_core_module()
            if elitea_core:
                logo_dir = elitea_core.platform_logo_path

                # Delete all logo files
                for old_file in glob.glob(str(logo_dir / "logo.*")):
                    try:
                        os.remove(old_file)
                    except Exception as e:
                        log.warning("Failed to delete logo file %s: %s", old_file, e)

        except Exception as e:
            log.warning("Failed to delete logo file: %s", e)

        # Update config to remove logo_url
        theme_data["logo_url"] = None
        try:
            update_custom_theme_config(self.module, theme_data)
        except RuntimeError as e:
            return {"error": str(e)}, 500

        return {"deleted": True}


class API(api_tools.APIBase):
    """Custom Theme Logo API"""

    url_params = [
        "<string:mode>",
    ]

    mode_handlers = {
        "administration": AdminAPI,
    }
