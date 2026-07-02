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

from ...services.platform_event import PlatformEventService, EventType, extract_plugins


def _get_installed_plugins(remote_runtimes, pylon_id):
    """Extract plugin versions for a pylon from remote_runtimes."""
    data = remote_runtimes.get(pylon_id, {})
    runtime_info = data.get("runtime_info", [])
    return extract_plugins(runtime_info)


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
        plugins_to_reload = request_data.get("plugins", [])

        user_id = None
        try:
            user_id = flask.g.auth.id
        except AttributeError:
            pass

        installed_plugins = _get_installed_plugins(self.module.remote_runtimes, pylon_id)

        if plugins_to_reload:
            log.info("Requesting plugin reload for pylon %s: %s", pylon_id, plugins_to_reload)
            try:
                with db.get_session() as session:
                    PlatformEventService.log_event(
                        session,
                        pylon_id=pylon_id,
                        event_type=EventType.RELOAD_REQUESTED,
                        user_id=user_id,
                        meta={"reload": plugins_to_reload, "plugins": installed_plugins},
                    )
                    session.commit()
            except Exception as e:
                log.warning("Failed to log reload event: %s", e)

            self.module.context.event_manager.fire_event(
                "bootstrap_runtime_update",
                {
                    "pylon_id": pylon_id,
                    "restart": False,
                    "reload": plugins_to_reload,
                },
            )
        else:
            log.info("Requesting full restart for pylon: %s", pylon_id)
            try:
                with db.get_session() as session:
                    PlatformEventService.log_event(
                        session,
                        pylon_id=pylon_id,
                        event_type=EventType.RESTART_REQUESTED,
                        user_id=user_id,
                        meta={"plugins": installed_plugins},
                    )
                    session.commit()
            except Exception as e:
                log.warning("Failed to log restart event: %s", e)

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
