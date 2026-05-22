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

import json
import flask

from pydantic import ValidationError

from pylon.core.tools import log
from tools import auth, api_tools, db

from ...models.moderation import ModerationState
from ...models.pd.moderation import ModerationStateListQuery, ModerationStateListResponse, ModerationStateResponse


class AdminAPI(api_tools.APIModeHandler):
    @auth.decorators.check_api({
        "permissions": ["admin.moderation"],
        "recommended_roles": {
            "administration": {"admin": True, "viewer": False, "editor": False},
            "default": {"admin": True, "viewer": False, "editor": False},
            "developer": {"admin": True, "viewer": False, "editor": False},
        }})
    def get(self):
        """List all moderation statuses with pagination"""
        try:
            query_params = ModerationStateListQuery(
                limit=flask.request.args.get("limit", 20, type=int),
                offset=flask.request.args.get("offset", 0, type=int),
                search=flask.request.args.get("search", None, type=str),
                status=flask.request.args.get("status", None, type=str),
                issue_type=flask.request.args.get("issue_type", None, type=str),
                project_id=flask.request.args.get("project_id", None, type=int),
                entity_id=flask.request.args.get("entity_id", None, type=str),
                sort_by=flask.request.args.get("sort_by", "created_at", type=str),
                sort_order=flask.request.args.get("sort_order", "desc", type=str),
            )
        except ValidationError as e:
            return {"error": "Validation error", "details": json.loads(e.json())}, 400

        with db.with_project_schema_session(None) as session:
            query = session.query(ModerationState)

            if query_params.search:
                query = query.filter(ModerationState.user_id == int(query_params.search))

            if query_params.status:
                query = query.filter(ModerationState.status == query_params.status.value)

            if query_params.issue_type:
                query = query.filter(ModerationState.issue_type == query_params.issue_type)

            if query_params.project_id:
                query = query.filter(ModerationState.project_id == query_params.project_id)

            if query_params.entity_id:
                query = query.filter(ModerationState.entity_id == query_params.entity_id)

            total = query.count()

            if hasattr(ModerationState, query_params.sort_by):
                order_column = getattr(ModerationState, query_params.sort_by)
                if query_params.sort_order.lower() == "desc":
                    query = query.order_by(order_column.desc())
                else:
                    query = query.order_by(order_column.asc())

            statuses = query.limit(query_params.limit).offset(query_params.offset).all()

            rows = []
            for status in statuses:
                rows.append(ModerationStateResponse(
                    id=status.id,
                    user_id=status.user_id,
                    project_id=status.project_id,
                    issue_type=status.issue_type,
                    entity_id=status.entity_id,
                    description=status.description,
                    status=status.status,
                    rejection_comment=status.rejection_comment,
                    meta=status.meta,
                    created_at=status.created_at.isoformat(timespec="seconds") if status.created_at else None,
                    updated_at=status.updated_at.isoformat(timespec="seconds") if status.updated_at else None,
                ))

            response = ModerationStateListResponse(total=total, rows=rows)
            return response.model_dump(), 200


class API(api_tools.APIBase):
    url_params = [
        "<string:mode>",
    ]

    mode_handlers = {
        'administration': AdminAPI,
    }
