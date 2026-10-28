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

from tools import auth, api_tools, register_openapi, this  # pylint: disable=E0401
from tools import context  # pylint: disable=E0401

from ...utils import project_data_delete as pdd
from .project_backup import PROJECT_DOWNLOAD_PERMISSION, PROMPT_LIB_MODE
from .project_restore import _is_own_personal_project


PROJECT_DATA_DELETE_PERMISSION = "models.project_data.delete"

DELETE_RPC_TIMEOUT = 600
COUNT_RPC_TIMEOUT = 30

RECOMMENDED_ROLES = {
    "administration": {"super_admin": True, "admin": True, "viewer": False, "editor": True},
    "default": {"super_admin": True, "admin": True, "viewer": False, "editor": True},
}


def _authorized(project_id):
    """ check_api lets project editors through (a private project's owner is one);
        the delete permission or owning the project is required on top """
    has_permission = auth.has_access(
        auth.resolve_permissions(mode=PROMPT_LIB_MODE, project_id=project_id),
        [PROJECT_DATA_DELETE_PERMISSION],
    )
    return pdd.is_authorized(has_permission, not has_permission and _is_own_personal_project(project_id))


def _denied():
    return {"ok": False, "error": "access_denied", "required": [PROJECT_DATA_DELETE_PERMISSION]}, 403


def _project_schema(project_id):
    from tools import project_constants as pc  # pylint: disable=E0401,C0415
    return pc["PROJECT_SCHEMA_TEMPLATE"].format(project_id)


def _visible_chat_ids(project_id, user_id):
    """ Ids of the chats the caller sees, or None when the project schema is missing """
    schema = _project_schema(project_id)
    connection = context.db.engine.raw_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "select 1 from information_schema.schemata where schema_name = %s", (schema,),
            )
            if cursor.fetchone() is None:
                return None
            cursor.execute(pdd.visible_chat_ids_sql(schema, user_id))
            ids = [row[0] for row in cursor.fetchall()]
        connection.rollback()
        return ids
    finally:
        connection.close()


def _rpc(timeout=DELETE_RPC_TIMEOUT):
    return context.rpc_manager.timeout(timeout)


def _entity_counts(project_id):
    """ type -> {count, blocked} for every type but chats; a type whose count fails is None """
    counts = {}
    try:
        counts.update(_rpc(COUNT_RPC_TIMEOUT).elitea_core_project_data_counts(project_id=project_id))
    except Exception:  # pylint: disable=W0703
        log.exception("project_data_delete: failed to count entities of project %s", project_id)
    try:
        counts[pdd.TYPE_CREDENTIALS] = {
            "count": _rpc(COUNT_RPC_TIMEOUT).configurations_count_section(
                project_id=project_id, section=pdd.CREDENTIALS_SECTION,
            ),
            "blocked": 0,
        }
    except Exception:  # pylint: disable=W0703
        log.exception("project_data_delete: failed to count credentials of project %s", project_id)
    return {name: counts.get(name) for name in pdd.SUPPORTED_TYPES if name != pdd.TYPE_CHATS}


def _delete_type(name, project_id, user_id, chat_ids):
    """ Delete one type: {deleted, failed, skipped}. An RPC error fails the type, never the request """
    calls = {
        pdd.TYPE_CHATS: lambda: _rpc().chat_delete_conversations_rpc(
            project_id=project_id, conversation_ids=chat_ids, folder_owner_id=user_id,
        ),
        pdd.TYPE_AGENTS: lambda: _rpc().applications_delete_by_kind(project_id=project_id, kind=pdd.KIND_AGENT),
        pdd.TYPE_PIPELINES: lambda: _rpc().applications_delete_by_kind(
            project_id=project_id, kind=pdd.KIND_PIPELINE,
        ),
        pdd.TYPE_SKILLS: lambda: _rpc().skills_delete_all(project_id=project_id),
        pdd.TYPE_TOOLKITS: lambda: _rpc().toolkits_delete_by_kind(project_id=project_id, kind=pdd.KIND_TOOLKIT),
        pdd.TYPE_MCPS: lambda: _rpc().toolkits_delete_by_kind(project_id=project_id, kind=pdd.KIND_MCP),
        pdd.TYPE_CREDENTIALS: lambda: _rpc().configurations_delete_section(
            project_id=project_id, section=pdd.CREDENTIALS_SECTION,
        ),
    }
    if name == pdd.TYPE_CHATS and not chat_ids:
        return {"deleted": 0, "failed": 0, "skipped": 0}
    try:
        result = calls[name]() or {}
    except Exception:  # pylint: disable=W0703
        log.exception("project_data_delete: %s delete failed in project %s", name, project_id)
        return {"deleted": 0, "failed": 1, "skipped": 0}
    return {key: result.get(key, 0) for key in ("deleted", "failed", "skipped")}


def _record_audit(project_id, user_id, types, results, status):
    event = pdd.build_audit_event(project_id, user_id, types, results, status)
    try:
        this.for_module("tracing").module.security_audit_record_autocommit(event)
    except Exception:  # pylint: disable=W0703
        # The data is gone already: the response still reports what happened
        log.exception("project_data_delete: audit record failed for project %s: %s", project_id, event)


class PromptLibAPI(api_tools.APIModeHandler):  # pylint: disable=R0903
    """ API """

    @register_openapi(
        name="Project Data Delete Summary",
        description="Number of items per type a bulk delete of project data would remove for the caller.",
        parameters=[
            {"name": "project_id", "in": "path", "schema": {"type": "integer"},
             "description": "Project ID."},
        ],
    )
    @auth.decorators.check_api({
        "permissions": [PROJECT_DOWNLOAD_PERMISSION],
        "recommended_roles": RECOMMENDED_ROLES,
    })
    def get(self, project_id: int, **kwargs):
        """ Process GET """
        _ = kwargs
        if not _authorized(project_id):
            return _denied()
        #
        user_id = auth.current_user().get("id")
        try:
            chat_ids = _visible_chat_ids(project_id, user_id)
        except Exception:  # pylint: disable=W0703
            log.exception("project_data_delete: failed to count chats of project %s", project_id)
            return {"ok": False, "error": "failed to resolve project chats"}, 500
        if chat_ids is None:
            return {"ok": False, "error": "project schema not found"}, 404
        #
        return {
            "ok": True,
            "types": {pdd.TYPE_CHATS: {"count": len(chat_ids), "blocked": 0}, **_entity_counts(project_id)},
        }, 200

    @register_openapi(
        name="Project Data Delete",
        description="Permanently delete all items of the selected types in the project: chats the "
                    "caller sees, agents, pipelines, skills, toolkits, mcps, credentials. Published or "
                    "embedded agents, pipelines and skills are skipped.",
        parameters=[
            {"name": "project_id", "in": "path", "schema": {"type": "integer"},
             "description": "Project ID."},
        ],
    )
    @auth.decorators.check_api({
        "permissions": [PROJECT_DOWNLOAD_PERMISSION],
        "recommended_roles": RECOMMENDED_ROLES,
    })
    def post(self, project_id: int, **kwargs):
        """ Process POST """
        _ = kwargs
        if not _authorized(project_id):
            return _denied()
        #
        try:
            types = pdd.parse_types(flask.request.get_json(silent=True))
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}, 400
        #
        user_id = auth.current_user().get("id")
        try:
            chat_ids = _visible_chat_ids(project_id, user_id) if pdd.TYPE_CHATS in types else []
        except Exception:  # pylint: disable=W0703
            log.exception("project_data_delete: failed to resolve chats of project %s", project_id)
            return {"ok": False, "error": "failed to resolve project chats"}, 500
        if chat_ids is None:
            return {"ok": False, "error": "project schema not found"}, 404
        #
        results = {name: _delete_type(name, project_id, user_id, chat_ids) for name in types}
        #
        status = pdd.aggregate_status(results)
        _record_audit(project_id, user_id, types, results, status)
        log.info(
            "project_data_delete: user %s deleted %s in project %s: %s",
            user_id, types, project_id, results,
        )
        #
        return {"ok": status != pdd.STATUS_FAILED, "status": status, "types": results}, 200


class API(api_tools.APIBase):  # pylint: disable=R0903
    """ API """

    url_params = [
        "<string:mode>/<int:project_id>",
    ]

    mode_handlers = {
        PROMPT_LIB_MODE: PromptLibAPI,
    }
