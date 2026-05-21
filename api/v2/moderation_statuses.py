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

""" API for moderation status management """

import flask

from pylon.core.tools import log
from tools import auth, api_tools, db

from ...models.moderation import ModerationState


class AdminAPI(api_tools.APIModeHandler):
    @auth.decorators.check_api({
        "permissions": ["admin.moderation"],
        "recommended_roles": {
            "administration": {"admin": True, "viewer": True, "editor": False},
            "default": {"admin": True, "viewer": False, "editor": False},
            "developer": {"admin": True, "viewer": False, "editor": False},
        }})
    def get(self):
        """List all moderation statuses with pagination"""
        limit = flask.request.args.get("limit", 20, type=int)
        offset = flask.request.args.get("offset", 0, type=int)

        user_id_filter = flask.request.args.get("user_id", None, type=int)
        status_filter = flask.request.args.get("status", None, type=str)
        issue_type_filter = flask.request.args.get("issue_type", None, type=str)
        project_id_filter = flask.request.args.get("project_id", None, type=int)
        entity_id_filter = flask.request.args.get("entity_id", None, type=int)

        sort_by = flask.request.args.get("sort_by", "created_at", type=str)
        sort_order = flask.request.args.get("sort_order", "desc", type=str)

        with db.with_project_schema_session(None) as session:
            query = session.query(ModerationState)

            if user_id_filter:
                query = query.filter(ModerationState.user_id == int(user_id_filter))

            if status_filter:
                query = query.filter(ModerationState.status == status_filter)

            if issue_type_filter:
                query = query.filter(ModerationState.issue_type == issue_type_filter)

            if project_id_filter:
                query = query.filter(ModerationState.project_id == project_id_filter)

            if entity_id_filter:
                query = query.filter(ModerationState.entity_id == entity_id_filter)

            total = query.count()

            if hasattr(ModerationState, sort_by):
                order_column = getattr(ModerationState, sort_by)
                if sort_order.lower() == "desc":
                    query = query.order_by(order_column.desc())
                else:
                    query = query.order_by(order_column.asc())

            statuses = query.limit(limit).offset(offset).all()

            rows = []
            for status in statuses:
                rows.append({
                    "id": status.id,
                    "user_id": status.user_id,
                    "project_id": status.project_id,
                    "issue_type": status.issue_type,
                    "entity_id": status.entity_id,
                    "description": status.description,
                    "status": status.status,
                    "rejection_comment": status.rejection_comment,
                    "meta": status.meta,
                    "created_at": status.created_at.isoformat(timespec="seconds") if status.created_at else None,
                    "updated_at": status.updated_at.isoformat(timespec="seconds") if status.updated_at else None,
                })

            return {
                "total": total,
                "rows": rows,
            }, 200


class API(api_tools.APIBase):
    url_params = [
        "<string:mode>",
    ]

    mode_handlers = {
        'administration': AdminAPI,
    }
