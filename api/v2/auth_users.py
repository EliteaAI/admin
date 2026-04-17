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

import flask  # pylint: disable=E0401,W0611

from pylon.core.tools import log  # pylint: disable=E0611,E0401,W0611

from tools import auth  # pylint: disable=E0401
from tools import api_tools  # pylint: disable=E0401


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=R0903
    """ API """

    @auth.decorators.check_api(["admin.auth.users"])
    def get(self):
        """ Process GET """
        result = auth.list_users_paginated(
            limit=flask.request.args.get("limit", 20, type=int),
            offset=flask.request.args.get("offset", 0, type=int),
            search=flask.request.args.get("search", None, type=str),
            user_type=flask.request.args.get("user_type", None, type=str),
            sort_by=flask.request.args.get("sort_by", "name", type=str),
            sort_order=flask.request.args.get("sort_order", "asc", type=str),
        )
        #
        for user in result["rows"]:
            if user["last_login"]:
                user["last_login"] = user["last_login"].isoformat(timespec="seconds")
        #
        return result

    @auth.decorators.check_api(["admin.auth.users"])
    def post(self):  # pylint: disable=R0912,R0914,R0915
        """ Process POST """
        data = flask.request.get_json()
        #
        if "action" not in data:
            return {"error": "action not set"}, 400
        #
        action = data["action"]
        #
        if action == "delete" and "users" not in data:
            return {"error": "users not set"}, 400
        #
        if action == "create" and "user_name" not in data:
            return {"error": "user_name not set"}, 400
        #
        if action == "create" and "user_email" not in data:
            return {"error": "user_email not set"}, 400
        #
        if action == "delete":
            for user in data["users"]:
                auth.delete_user(user["id"])
        #
        if action == "create":
            user_id = auth.add_user(data["user_email"], data["user_name"])
            auth.add_user_group(user_id, 1)
        #
        if action == "toggle_admin":
            if "user_id" not in data:
                return {"error": "user_id not set"}, 400
            if "is_admin" not in data:
                return {"error": "is_admin not set"}, 400
            if data["is_admin"]:
                auth.assign_user_to_role(
                    user_id=data["user_id"],
                    role_name="admin",
                    mode="administration",
                )
            else:
                auth.remove_user_from_role(
                    user_id=data["user_id"],
                    role_name="admin",
                    mode="administration",
                )
        #
        if action == "toggle_super_admin":
            if "user_id" not in data:
                return {"error": "user_id not set"}, 400
            if "is_super_admin" not in data:
                return {"error": "is_super_admin not set"}, 400
            current_permissions = auth.resolve_permissions(mode="administration")
            if not auth.has_access(current_permissions, ["admin.auth.users.super_admin"]):
                return {"error": "Only super_admin can assign/revoke super_admin role"}, 403
            if data["is_super_admin"]:
                auth.assign_user_to_role(
                    user_id=data["user_id"],
                    role_name="super_admin",
                    mode="administration",
                )
            else:
                auth.remove_user_from_role(
                    user_id=data["user_id"],
                    role_name="super_admin",
                    mode="administration",
                )
        #
        return {
            "ok": True,
        }


class API(api_tools.APIBase):  # pylint: disable=R0903
    """ API """

    url_params = [
        "<string:mode>",
    ]

    mode_handlers = {
        'administration': AdminAPI,
    }
