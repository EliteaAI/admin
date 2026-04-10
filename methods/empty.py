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

""" Method """

import flask
from flask import g, request

from pylon.core.tools import log  # pylint: disable=E0611,E0401
from pylon.core.tools import web  # pylint: disable=E0611,E0401

from tools import auth  # pylint: disable=E0401
from tools import theme  # pylint: disable=E0401


class Method:  # pylint: disable=E1101,R0903
    """
        Method Resource

        self is pointing to current Module instance

        web.method decorator takes zero or one argument: method name
        Note: web.method decorator must be the last decorator (at top)

    """

    @web.init()
    def _init(self):
        self.context.app.before_request(self.before_request_hook)

    @web.method("before_request_hook")
    def _before_request_hook(  # pylint: disable=R0913
            self,
    ):
        if flask.g.auth.id == "-":
            return
        #
        theme_project_mode_endpoints = [
            "theme.route_section",
            "theme.route_section_subsection",
            "theme.route_section_subsection_page",
        ]
        #
        if self.descriptor.config.get("theme_index_is_project_mode", True):
            theme_project_mode_endpoints.append("theme.index")
        #
        project_mode_target = \
            (
                    request.endpoint is not None and
                    request.endpoint in theme_project_mode_endpoints
            ) or (
                    request.endpoint is not None and
                    request.endpoint.startswith("theme.route_mode_") and
                    (
                            request.view_args is None or
                            request.view_args.get("mode", "default") == 'default'
                    )
            )
        #
        empty_page_target = \
            (
                    request.endpoint == "theme.route_section_subsection_page" and
                    request.view_args is not None and
                    request.view_args.get("section", "unknown") == "system" and
                    request.view_args.get("subsection", "unknown") == "status" and
                    request.view_args.get("page", "unknown") == "empty"
            )
        #
        if not project_mode_target or empty_page_target:
            return

        #
        user_projects = self.context.rpc_manager.call.list_user_projects(flask.g.auth.id)
        user_is_admin = auth.resolve_permissions(mode='administration')

        if user_is_admin and not user_projects:
            return flask.redirect(
                flask.url_for(
                    "theme.route_mode_section",
                    mode='administration', section='projects'
                )
            )
        selected_project = self.context.rpc_manager.call.project_get_id()
        #
        if not user_projects or not selected_project:
            log.info("--- [REDIRECT] --- Request endpoint: %s", request.endpoint)
            log.info("--- [REDIRECT] --- Request view_args: %s", request.view_args)
            #
            return flask.redirect(
                flask.url_for(
                    "theme.route_section_subsection_page",
                    section="system", subsection="status", page="empty",
                )
            )
