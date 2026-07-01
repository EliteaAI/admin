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

from tools import auth, db  # pylint: disable=E0401
from tools import api_tools, register_openapi  # pylint: disable=E0401

from ...services.platform_status import PlatformStatusService


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=R0903
    """ API """

    @register_openapi(
        name="Restart Pylon or Reload Plugins",
        description="Trigger a full pylon restart or selective plugin reload.",
        parameters=[
            {"name": "pylon_id", "in": "path", "schema": {"type": "string"},
             "description": "Target pylon identifier."},
        ],
    )
    @auth.decorators.check_api({
        "permissions": ["runtime.plugins"],
        "recommended_roles": {
            "administration": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
            "default": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
            "developer": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
        }})
    def post(self, pylon_id):
        """ Reload plugins on a specific pylon """
        request_data = flask.request.get_json() or {}
        plugins = request_data.get("plugins", [])

        # Extract user context
        user_id = None
        try:
            user_id = flask.g.auth.id
        except Exception:
            pass

        is_full_restart = not plugins

        #
        if plugins:
            log.info("Requesting plugin reload for pylon %s: %s", pylon_id, plugins)
            self.module.context.event_manager.fire_event(
                "bootstrap_runtime_update",
                {
                    "pylon_id": pylon_id,
                    "restart": False,
                    "reload": plugins,
                },
            )
        else:
            # Create lifecycle flag with start_time set immediately
            # (we set start_time here because the pylon_stopping event from target
            # pylon may not reach us before it shuts down)
            try:
                with db.get_session() as session:
                    PlatformStatusService.create_planned_event(
                        session,
                        pylon_id=pylon_id,
                        event_type='restart',
                        user_id=user_id,
                        set_start_time=True,
                    )
                    session.commit()
            except Exception as e:
                log.warning("Failed to create lifecycle flag: %s", e)

            log.info("Requesting full restart for pylon: %s", pylon_id)
            self.module.context.event_manager.fire_event(
                "bootstrap_runtime_update",
                {
                    "pylon_id": pylon_id,
                    "restart": True,
                    "pylon_pid": 1,
                },
            )
        #
        return {"ok": True}


class API(api_tools.APIBase):  # pylint: disable=R0903
    """ API """

    url_params = [
        "<string:mode>/<string:pylon_id>",
    ]

    mode_handlers = {
        'administration': AdminAPI,
    }
