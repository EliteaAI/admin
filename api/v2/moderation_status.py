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

import json
import flask
from datetime import datetime, timezone

from pydantic import ValidationError

from pylon.core.tools import log
from tools import auth, api_tools, db, register_openapi

from ...models.moderation import ModerationState
from ...models.pd.moderation import ModerationStateCreate, ModerationStateUpdate, ModerationStateResponse


class AdminAPI(api_tools.APIModeHandler):
    @register_openapi(
        name="Update Moderation Status",
        description="Update a moderation status entry (approve/reject).",
        request_body=ModerationStateUpdate
    )
    @auth.decorators.check_api({
        "permissions": ["admin.moderation.edit"],
        "recommended_roles": {
            "administration": {"admin": True, "viewer": False, "editor": True},
            "default": {"admin": True, "viewer": False, "editor": False},
            "developer": {"admin": True, "viewer": False, "editor": False},
        }})
    def put(self):
        try:
            data = ModerationStateUpdate(**flask.request.json)
        except ValidationError as e:
            return {"error": "Validation error", "details": json.loads(e.json())}, 400

        with db.with_project_schema_session(None) as session:
            moderation_state = session.query(ModerationState).filter(
                ModerationState.id == data.id,
            ).first()

            if not moderation_state:
                return {"error": "Moderation status not found"}, 404

            if data.status:
                moderation_state.status = data.status.value

            if data.rejection_comment is not None:
                moderation_state.rejection_comment = data.rejection_comment

            if data.meta is not None:
                moderation_state.meta = data.meta

            moderation_state.updated_at = datetime.now(timezone.utc)

            session.commit()
            session.refresh(moderation_state)

            if data.status and data.status.value in ("approved", "rejected"):
                try:
                    self.module.context.event_manager.fire_event(
                        'notifications_stream', {
                            'project_id': moderation_state.project_id,
                            'user_id': moderation_state.user_id,
                            'meta': {
                                'issue_type': moderation_state.issue_type,
                                'entity_id': moderation_state.entity_id,
                                'status': moderation_state.status,
                                'rejection_comment': moderation_state.rejection_comment,
                                'message': (
                                    f'Your {moderation_state.issue_type} moderation request has been {moderation_state.status}.'
                                    + (f' Reason: {moderation_state.rejection_comment}' if moderation_state.rejection_comment else '')
                                ),
                            },
                            'event_type': f'moderation_{moderation_state.status}',
                        }
                    )
                except Exception as e:
                    log.warning('Failed to send moderation notification: %s', e)

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


class DefaultAPI(api_tools.APIModeHandler):
    @register_openapi(
        name="Get Entity Moderation Status",
        description="Get moderation statuses for an entity.",
        parameters=[
            {"name": "project_id", "in": "path", "schema": {"type": "integer"}},
            {"name": "entity_id", "in": "path", "schema": {"type": "string"}},
            {"name": "issue_type", "in": "query", "schema": {"type": "string"}}
        ]
    )
    @auth.decorators.check_api({
        "permissions": ["admin.moderation.view"],
        "recommended_roles": {
            "administration": {"admin": True, "viewer": True, "editor": True},
            "default": {"admin": True, "viewer": True, "editor": True},
            "developer": {"admin": True, "viewer": True, "editor": True},
        }})
    def get(self, project_id: int, entity_id: str):
        issue_type = flask.request.args.get("issue_type", None, type=str)

        current_user = auth.current_user()
        user_id = current_user.get('id') if current_user else None

        with db.with_project_schema_session(None) as session:
            query = session.query(ModerationState).filter(
                ModerationState.project_id == project_id,
                ModerationState.entity_id == entity_id,
                ModerationState.user_id == user_id,
            )

            if issue_type:
                query = query.filter(ModerationState.issue_type == issue_type)

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

            return {"total": len(rows), "rows": rows}, 200

    @register_openapi(
        name="Create Moderation Status",
        description="Submit a moderation request for an entity.",
        parameters=[
            {"name": "project_id", "in": "path", "schema": {"type": "integer"}},
            {"name": "entity_id", "in": "path", "schema": {"type": "string"}}
        ],
        request_body=ModerationStateCreate
    )
    @auth.decorators.check_api({
        "permissions": ["admin.moderation.create"],
        "recommended_roles": {
            "administration": {"admin": True, "viewer": True, "editor": True},
            "default": {"admin": True, "viewer": True, "editor": True},
            "developer": {"admin": True, "viewer": True, "editor": True},
        }})
    def post(self, project_id: int, entity_id: str):
        try:
            data = ModerationStateCreate(**flask.request.json)
        except ValidationError as e:
            return {"error": "Validation error", "details": json.loads(e.json())}, 400

        current_user = auth.current_user()
        user_id = current_user.get('id') if current_user else None

        with db.with_project_schema_session(None) as session:
            new_status = ModerationState(
                user_id=user_id,
                project_id=project_id,
                issue_type=data.issue_type,
                entity_id=entity_id,
                description=data.description,
                status=data.status.value,
                meta=data.meta,
            )
            session.add(new_status)
            session.commit()
            session.refresh(new_status)

            return ModerationStateResponse(
                id=new_status.id,
                user_id=new_status.user_id,
                project_id=new_status.project_id,
                issue_type=new_status.issue_type,
                entity_id=new_status.entity_id,
                description=new_status.description,
                status=new_status.status,
                rejection_comment=new_status.rejection_comment,
                meta=new_status.meta,
                created_at=new_status.created_at.isoformat(timespec="seconds") if new_status.created_at else None,
            ).model_dump(), 201




class API(api_tools.APIBase):
    url_params = [
        "<string:mode>",
        "<string:mode>/<int:project_id>/<string:entity_id>",
    ]

    mode_handlers = {
        'administration': AdminAPI,
        'default': DefaultAPI,
    }
