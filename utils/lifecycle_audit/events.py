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

""" Lifecycle audit payloads and actor contexts

Same payload contract as auth_core ``tools/lifecycle_audit.py``; pylon_main adds the project
name/type snapshot because it owns projects.
"""

import datetime
import uuid

CTX_KEYS = ("actor_type", "actor_id", "actor_name", "actor_email", "source", "request_id")

SYSTEM_CTX = {"actor_type": "system", "actor_id": None, "actor_name": "System",
              "actor_email": None, "source": "system", "request_id": None}
SCIM_CTX = {"actor_type": "service", "actor_id": None, "actor_name": "SCIM provisioning",
            "actor_email": None, "source": "provisioning", "request_id": None}

PLATFORM_ADMIN_ROLES = frozenset({"super_admin", "admin"})
PROJECT_ADMIN_ROLES = frozenset({"admin"})

PERSONAL_PREFIX = "project_user_"

SECRET_MARKERS = ("password", "token", "secret", "credential", "key")


def project_type(name):
    """ private for personal projects (named project_user_<uid>), else team """
    return "private" if str(name or "").startswith(PERSONAL_PREFIX) else "team"


def actor(ctx):
    """ Actor fields; unknown when no context was passed, never a guessed user """
    if not ctx:
        return {key: None for key in CTX_KEYS} | {"actor_type": "unknown"}
    result = {key: ctx.get(key) for key in CTX_KEYS}
    result["actor_type"] = result["actor_type"] or "unknown"
    return result


def scrub(value):
    """ Drop secret-shaped keys at any depth """
    if isinstance(value, dict):
        return {
            key: scrub(item) for key, item in value.items()
            if not any(marker in str(key).lower() for marker in SECRET_MARKERS)
        }
    if isinstance(value, (list, tuple)):
        return [scrub(item) for item in value]
    return value


def admin_access(before, after, admin_roles):
    """ granted / revoked when an administrator role is gained / lost, else None """
    had = bool(set(before or ()) & admin_roles)
    has = bool(set(after or ()) & admin_roles)
    if had == has:
        return None
    return "granted" if has else "revoked"


def build(  # pylint: disable=R0913
        event_type, ctx, scope, project=None, user=None, roles_before=None, roles_after=None,
        changes=None, details=None, admin_roles=None,
):
    """ One audit payload """
    project = project or {}
    user = user or {}
    event = {
        "event_id": str(uuid.uuid4()),
        "occurred_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event_type": event_type,
        "scope": scope,
        "result": "success",
        "failure_reason": None,
        "imported": False,
        "project_id": project.get("id"),
        "project_name": project.get("name"),
        "project_type": project.get("type") or (project_type(project["name"]) if project.get("name") else None),
        "user_id": user.get("id"),
        "user_name": user.get("name"),
        "user_email": user.get("email"),
        "roles_before": roles_before,
        "roles_after": roles_after,
        "admin_access": admin_access(roles_before, roles_after, admin_roles) if admin_roles else None,
        "changes": scrub(changes or {}),
        "details": scrub(details or {}),
    }
    event.update(actor(ctx))
    return event


def ctx_from_auth(auth, user=None, request_id=None):
    """ Context of a request: a signed-in user is ui, a token is api, anything else System """
    auth_type = getattr(auth, "type", None)
    auth_id = getattr(auth, "id", None)
    if auth_type not in ("user", "token") or not isinstance(auth_id, int):
        return dict(SYSTEM_CTX, request_id=request_id)
    user = user or {}
    return {
        "actor_type": "user",
        "actor_id": auth_id,
        "actor_name": user.get("name"),
        "actor_email": user.get("email"),
        "source": "ui" if auth_type == "user" else "api",
        "request_id": request_id,
    }


def ctx_for_task(executing_user_id, user=None):
    """ Admin task run by a user (api), or a scheduled job with no executor (System) """
    if executing_user_id is None:
        return dict(SYSTEM_CTX)
    user = user or {}
    return {
        "actor_type": "user",
        "actor_id": executing_user_id,
        "actor_name": user.get("name"),
        "actor_email": user.get("email"),
        "source": "api",
        "request_id": None,
    }
