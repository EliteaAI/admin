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

""" Bulk delete of project data: requested types, the outcome and its audit event

Which items of a type are deleted or skipped is decided by the plugins that own
them (elitea_core, configurations), not here.
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

STATUS_SUCCESS = "success"
STATUS_PARTIAL = "partial"
STATUS_FAILED = "failed"
# The time budget ran out or a type's outcome is unknown: running again finishes the job
STATUS_INCOMPLETE = "incomplete"

AUDIT_REASON_CODE = "PROJECT_DATA_DELETED"
AUDIT_STARTED_REASON_CODE = "PROJECT_DATA_DELETE_STARTED"

# Seconds one run may spend deleting. Each bulk RPC stops on its own when its share runs out,
# so a run never outlives its response; the RPC timeout leaves a margin for the item in progress
TIME_BUDGET = 540
RPC_TIMEOUT_MARGIN = 60

RESULT_KEYS = ("deleted", "failed", "skipped", "remaining")

TARGET_REF_MAX = 256


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


def visible_chat_ids_sql(schema, user_id):
    """ Chats the caller sees: the ones counted, backed up and deleted """
    return chat_backup.conversation_scope_sql(schema, user_id)


def is_authorized(has_permission, owns_project):
    """ Team projects need the delete permission (admin); a private project is
        authorized by ownership, its owner is never its admin """
    return bool(has_permission or owns_project)


def type_result(result=None, unknown=False):
    """ One type's result. remaining is None for a type not run or with an unknown outcome """
    result = result or {}
    item = {key: result.get(key, 0) for key in RESULT_KEYS}
    if unknown:
        item["remaining"] = None
        item["unknown"] = True
    return item


def not_started():
    """ A type the run did not reach: nothing deleted, everything left """
    return {"deleted": 0, "failed": 0, "skipped": 0, "remaining": None}


def is_incomplete(item):
    return item.get("unknown", False) or item.get("remaining", 0) != 0


def aggregate_status(results):
    if any(is_incomplete(item) for item in results.values()):
        return STATUS_INCOMPLETE
    deleted = sum(item.get("deleted", 0) for item in results.values())
    failed = sum(item.get("failed", 0) for item in results.values())
    if not failed:
        return STATUS_SUCCESS
    return STATUS_PARTIAL if deleted else STATUS_FAILED


def audit_outcome(results, status):
    if status == STATUS_SUCCESS:
        return "success"
    if any(item.get("unknown") for item in results.values()):
        return "target_outcome_unknown"
    return "failed"


def build_started_audit_event(project_id, actor_user_id, types, operation_id):
    """ Written before the first delete, so a run cut short still has a record of who started it """
    return {
        "event_type": "lifecycle",
        "reason_code": AUDIT_STARTED_REASON_CODE,
        "project_id": project_id,
        "caller_ref": "user:{}".format(actor_user_id),
        "operation_id": operation_id,
        "target_ref": ",".join(types),
    }


def _ref_part(name, item):
    part = "{}=d{},f{},s{}".format(name, item.get("deleted", 0), item.get("failed", 0), item.get("skipped", 0))
    remaining = item.get("remaining", 0)
    if remaining is None:
        part += ",r?"
    elif remaining:
        part += ",r{}".format(remaining)
    return part


def build_audit_event(project_id, actor_user_id, types, results, status, operation_id=None):
    """ Security audit event: references and counts only. target_ref is
        type=d<deleted>,f<failed>,s<skipped>[,r<remaining>] per type (r? when unknown),
        compact to stay within the 256 characters the audit allows; summed when it does not fit """
    target_ref = ";".join(_ref_part(name, results.get(name, {})) for name in types)
    if len(target_ref) > TARGET_REF_MAX:
        # Too long per type: the types and their summed counts
        items = [results.get(name, {}) for name in types]
        totals = {key: sum(item.get(key) or 0 for item in items) for key in ("deleted", "failed", "skipped")}
        totals["remaining"] = None if any(item.get("remaining") is None for item in items) else sum(
            item.get("remaining", 0) for item in items
        )
        target_ref = _ref_part(",".join(types), totals)
    event = {
        "event_type": "lifecycle",
        "reason_code": AUDIT_REASON_CODE,
        "project_id": project_id,
        "caller_ref": "user:{}".format(actor_user_id),
        "target_ref": target_ref,
        "outcome": audit_outcome(results, status),
    }
    if operation_id:
        event["operation_id"] = operation_id
    return event

