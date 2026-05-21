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

""" API for individual moderation status """

import flask
from datetime import datetime

try:
    from pydantic.v1 import ValidationError
except:  # pylint: disable=W0702
    from pydantic import ValidationError

from pylon.core.tools import log
from tools import auth, api_tools, db

from ...models.moderation import ModerationState
from ...models.pd.moderation import ModerationStateCreate, ModerationStateUpdate


class AdminAPI(api_tools.APIModeHandler):
    @auth.decorators.check_api({
        "permissions": ["admin.moderation"],
        "recommended_roles": {
            "administration": {"admin": True, "viewer": True, "editor": False},
            "default": {"admin": True, "viewer": False, "editor": False},
            "developer": {"admin": True, "viewer": False, "editor": False},
        }})
    def get(self, user_id: int):
        """Get moderation statuses for a specific user"""
        issue_type = flask.request.args.get("issue_type", None, type=str)
        project_id = flask.request.args.get("project_id", None, type=int)
        entity_id = flask.request.args.get("entity_id", None, type=int)

        with db.with_project_schema_session(None) as session:
            query = session.query(ModerationState).filter(
                ModerationState.user_id == user_id
            )

            if issue_type:
                query = query.filter(ModerationState.issue_type == issue_type)

            if project_id:
                query = query.filter(ModerationState.project_id == project_id)

            if entity_id:
                query = query.filter(ModerationState.entity_id == entity_id)

            statuses = query.order_by(ModerationState.created_at.desc()).all()

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
                "total": len(rows),
                "rows": rows,
            }, 200

    @auth.decorators.check_api({
        "permissions": ["admin.moderation"],
        "recommended_roles": {
            "administration": {"admin": True, "viewer": False, "editor": True},
            "default": {"admin": True, "viewer": False, "editor": False},
            "developer": {"admin": True, "viewer": False, "editor": False},
        }})
    def post(self, user_id: int):
        """Create a new moderation status for a user"""
        try:
            data = ModerationStateCreate(**flask.request.json)
        except ValidationError as e:
            return {"error": "Validation error", "details": e.errors()}, 400

        with db.with_project_schema_session(None) as session:
            new_status = ModerationState(
                user_id=user_id,
                project_id=data.project_id,
                issue_type=data.issue_type,
                entity_id=data.entity_id,
                description=data.description,
                status=data.status,
                meta=data.meta,
            )
            session.add(new_status)
            session.commit()
            session.refresh(new_status)

            return {
                "id": new_status.id,
                "user_id": new_status.user_id,
                "project_id": new_status.project_id,
                "issue_type": new_status.issue_type,
                "entity_id": new_status.entity_id,
                "description": new_status.description,
                "status": new_status.status,
                "rejection_comment": new_status.rejection_comment,
                "meta": new_status.meta,
                "created_at": new_status.created_at.isoformat(timespec="seconds") if new_status.created_at else None,
                "updated_at": new_status.updated_at.isoformat(timespec="seconds") if new_status.updated_at else None,
            }, 201

    @auth.decorators.check_api({
        "permissions": ["admin.moderation"],
        "recommended_roles": {
            "administration": {"admin": True, "viewer": False, "editor": True},
            "default": {"admin": True, "viewer": False, "editor": False},
            "developer": {"admin": True, "viewer": False, "editor": False},
        }})
    def put(self, user_id: int):
        """Update an existing moderation status"""
        try:
            data = ModerationStateUpdate(**flask.request.json)
        except ValidationError as e:
            return {"error": "Validation error", "details": e.errors()}, 400

        with db.with_project_schema_session(None) as session:
            moderation_state = session.query(ModerationState).filter(
                ModerationState.id == data.id,
                ModerationState.user_id == user_id
            ).first()

            if not moderation_state:
                return {"error": "Moderation status not found"}, 404

            if data.status:
                moderation_state.status = data.status

            if data.rejection_comment is not None:
                moderation_state.rejection_comment = data.rejection_comment

            if data.meta is not None:
                moderation_state.meta = data.meta

            moderation_state.updated_at = datetime.utcnow()

            session.commit()
            session.refresh(moderation_state)

            return {
                "id": moderation_state.id,
                "user_id": moderation_state.user_id,
                "project_id": moderation_state.project_id,
                "issue_type": moderation_state.issue_type,
                "entity_id": moderation_state.entity_id,
                "description": moderation_state.description,
                "status": moderation_state.status,
                "rejection_comment": moderation_state.rejection_comment,
                "meta": moderation_state.meta,
                "created_at": moderation_state.created_at.isoformat(timespec="seconds") if moderation_state.created_at else None,
                "updated_at": moderation_state.updated_at.isoformat(timespec="seconds") if moderation_state.updated_at else None,
            }, 200


class API(api_tools.APIBase):
    url_params = [
        "<string:mode>/<int:user_id>",
    ]

    mode_handlers = {
        'administration': AdminAPI,
    }
