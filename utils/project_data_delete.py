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

""" Bulk delete of project data: requested types, how items are sorted into
them, the outcome and its audit event

The kind rules mirror elitea_core (toolkits_listing, list_applications
agents_type) and the published guards of the single deletes; keep them in sync.
"""

from . import chat_backup

TYPE_CHATS = "chats"
TYPE_AGENTS = "agents"
TYPE_PIPELINES = "pipelines"
TYPE_SKILLS = "skills"
TYPE_TOOLKITS = "toolkits"
TYPE_MCPS = "mcps"
TYPE_CREDENTIALS = "credentials"

# Processing order: applications before toolkits, so agent-as-tool rows go with
# their agent; credentials last, after the toolkits that use them
SUPPORTED_TYPES = (
    TYPE_CHATS, TYPE_AGENTS, TYPE_PIPELINES, TYPE_SKILLS, TYPE_TOOLKITS, TYPE_MCPS, TYPE_CREDENTIALS,
)

KIND_AGENT = "agent"
KIND_PIPELINE = "pipeline"
KIND_TOOLKIT = "toolkit"
KIND_MCP = "mcp"

CREDENTIALS_SECTION = "credentials"

# A single delete refuses these; the bulk delete skips them
BLOCKED_STATUSES = frozenset(("published", "embedded"))

STATUS_SUCCESS = "success"
STATUS_PARTIAL = "partial"
STATUS_FAILED = "failed"

AUDIT_REASON_CODE = "PROJECT_DATA_DELETED"


def parse_types(payload):
    """ Requested types, in order and without duplicates; raises ValueError when
        none is given or any is unknown """
    types = (payload or {}).get("types")
    if not isinstance(types, list) or not types:
        raise ValueError("types must be a non-empty list")
    #
    unknown = [item for item in types if item not in SUPPORTED_TYPES]
    if unknown:
        raise ValueError("unsupported types: {}".format(", ".join(str(item) for item in unknown)))
    #
    return [name for name in SUPPORTED_TYPES if name in types]


def toolkit_kind(tool_type, meta):
    """ mcp / toolkit, or None for an agent-as-tool entry (it belongs to its agent) """
    if tool_type == "application":
        return None
    if tool_type == "mcp" or (meta or {}).get("mcp"):
        return KIND_MCP
    return KIND_TOOLKIT


def application_kind(version_agent_types):
    """ An application with any pipeline version is a pipeline """
    return KIND_PIPELINE if KIND_PIPELINE in version_agent_types else KIND_AGENT


def is_blocked(version_statuses):
    return any(status in BLOCKED_STATUSES for status in version_statuses)


def visible_chat_ids_sql(schema, user_id):
    """ Chats the caller sees: the ones counted, backed up and deleted """
    return chat_backup.conversation_scope_sql(schema, user_id)


def is_authorized(has_permission, owns_project):
    """ Team projects need the delete permission (admin); a private project is
        authorized by ownership, its owner is never its admin """
    return bool(has_permission or owns_project)


def aggregate_status(results):
    deleted = sum(item.get("deleted", 0) for item in results.values())
    failed = sum(item.get("failed", 0) for item in results.values())
    if not failed:
        return STATUS_SUCCESS
    return STATUS_PARTIAL if deleted else STATUS_FAILED


def build_audit_event(project_id, actor_user_id, types, results, status):
    """ Security audit event: references and counts only. target_ref is
        type=d<deleted>,f<failed>,s<skipped> per type, compact to stay within
        the 256 characters the audit allows """
    target_ref = ";".join(
        "{}=d{},f{},s{}".format(
            name, results.get(name, {}).get("deleted", 0), results.get(name, {}).get("failed", 0),
            results.get(name, {}).get("skipped", 0),
        )
        for name in types
    )
    return {
        "event_type": "lifecycle",
        "reason_code": AUDIT_REASON_CODE,
        "project_id": project_id,
        "caller_ref": "user:{}".format(actor_user_id),
        "target_ref": target_ref,
        "outcome": "success" if status == STATUS_SUCCESS else "failed",
    }

