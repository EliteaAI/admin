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

""" Task """

import json

from tools import context, log, auth  # pylint: disable=E0401

PROTECTED_USER_ID = 1
PERSONAL_PROJECT_PREFIX = "project_user_"


def _to_list(value):
    """ Coerce a scalar, comma-separated string, or list into a list """
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return [value]


def _to_bool(value, default=False):
    """ Coerce common truthy/falsy representations into a bool """
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def parse_param(param):
    """
        Parse the task 'param' field into a dict of task parameters.

        Accepts a JSON object string (preferred, matches the task's
        documented examples), or falls back to a simple
        'key=value,key=value' string for quick manual runs.
    """
    param = (param or "").strip()
    if not param:
        return {}
    #
    if param.startswith("{"):
        return json.loads(param)
    #
    parsed = {}
    for pair in param.split(","):
        pair = pair.strip()
        if not pair or "=" not in pair:
            continue
        key, _, value = pair.partition("=")
        parsed[key.strip()] = value.strip()
    return parsed


def is_personal_project(project):
    """ Check whether a project dict represents a per-user personal project """
    return bool(project) and str(project.get("name", "")).startswith(PERSONAL_PROJECT_PREFIX)


def is_protected_user(user, executing_user_id=None):
    """ Check whether a user must never be suspended/deleted by these tasks """
    if not user:
        return True
    #
    from plugins.projects.rpc.poc import is_system_user  # pylint: disable=E0401,C0415
    #
    if int(user["id"]) == PROTECTED_USER_ID:
        return True
    if is_system_user(user.get("email", "")):
        return True
    if executing_user_id is not None and int(user["id"]) == int(executing_user_id):
        return True
    return False


def _resolve_users(user_ids, user_emails):
    """ Resolve a mixed list of user ids / emails into user dicts, reporting misses """
    resolved = {}
    missing = []
    #
    if user_ids:
        for user in auth.list_users(user_ids=[int(uid) for uid in user_ids]):
            resolved[int(user["id"])] = user
        for uid in user_ids:
            if int(uid) not in resolved:
                missing.append(f"user_id={uid}")
    #
    for email in user_emails or []:
        try:
            user = auth.get_user(email=email)
        except RuntimeError:
            missing.append(f"user_email={email}")
            continue
        resolved[int(user["id"])] = user
    #
    return list(resolved.values()), missing


def suspend_projects_and_users(*args, **kwargs):  # pylint: disable=W0613,R0912,R0914,R0915
    """
        Suspend private projects with their owners, or team projects only.
        Param: JSON object, e.g. {"scope": "team_projects", "project_ids": [1,2], "dry_run": true}.
        scope: 'private_with_users' or 'team_projects'. Selectors: project_ids, user_ids,
        user_emails, or "all": true. Optional: reason, dry_run (default true). Destructive when dry_run=false.
    """
    from plugins.projects.api.v2.project import delete_project  # noqa: F401  pylint: disable=E0401,C0415,W0611
    from plugins.projects.models.project import Project  # pylint: disable=E0401,C0415
    from tools import db  # pylint: disable=E0401,C0415
    #
    try:
        params = parse_param(kwargs.get("param", ""))
    except (json.JSONDecodeError, ValueError) as exc:
        log.error("Invalid param: %s", exc)
        return
    #
    scope = params.get("scope")
    if scope not in {"private_with_users", "team_projects"}:
        log.error("Invalid or missing 'scope' (must be 'private_with_users' or 'team_projects'): %s", scope)
        return
    #
    project_ids = _to_list(params.get("project_ids"))
    user_ids = _to_list(params.get("user_ids"))
    user_emails = _to_list(params.get("user_emails"))
    process_all = _to_bool(params.get("all"), default=False)
    dry_run = _to_bool(params.get("dry_run"), default=True)
    reason = params.get("reason") or ""
    #
    if not process_all and not project_ids and not user_ids and not user_emails:
        log.error("At least one selector (project_ids/user_ids/user_emails) is required unless 'all' is true")
        return
    #
    processed = suspended = skipped = failed = 0
    #
    log.info(
        "Starting suspend_projects_and_users: scope=%s dry_run=%s reason=%r",
        scope, dry_run, reason,
    )
    #
    if scope == "team_projects":
        if process_all:
            projects = [
                project for project in context.rpc_manager.timeout(120).project_list(
                    filter_={"create_success": True},
                )
                if not is_personal_project(project)
            ]
        else:
            projects = []
            for project_id in project_ids:
                project = context.rpc_manager.call.project_get_by_id(int(project_id))
                if not project:
                    log.error("Project not found, skipping: %s", project_id)
                    failed += 1
                    continue
                if is_personal_project(project):
                    log.info("Skipping personal project (scope=team_projects): %s", project)
                    skipped += 1
                    continue
                projects.append(project)
        #
        for project in projects:
            processed += 1
            if project.get("suspended"):
                log.info("Already suspended, skipping: project_id=%s", project["id"])
                skipped += 1
                continue
            #
            if dry_run:
                log.info("[DRY RUN] Would suspend team project: %s", project)
                continue
            #
            try:
                with db.with_project_schema_session(None) as session:
                    db_project = session.query(Project).where(Project.id == project["id"]).first()
                    if not db_project:
                        raise RuntimeError(f"Project {project['id']} disappeared before suspension")
                    db_project.suspended = True
                    session.commit()
                log.info("Suspended team project: project_id=%s", project["id"])
                suspended += 1
            except Exception as exc:  # pylint: disable=W0703
                log.exception("Failed to suspend project_id=%s: %s", project["id"], exc)
                failed += 1
    #
    else:  # private_with_users
        if process_all:
            users = auth.list_users()
        else:
            users, missing = _resolve_users(user_ids, user_emails)
            for entry in missing:
                log.error("User not found, skipping: %s", entry)
                failed += 1
        #
        for user in users:
            processed += 1
            #
            if is_protected_user(user, executing_user_id=kwargs.get("_user_id")):
                log.info("Skipping protected user: id=%s email=%s", user["id"], user.get("email"))
                skipped += 1
                continue
            #
            personal_project_id = context.rpc_manager.call.projects_get_personal_project_id(user["id"])
            personal_project = (
                context.rpc_manager.call.project_get_by_id(personal_project_id)
                if personal_project_id else None
            )
            #
            if not personal_project:
                log.error("No personal project found for user_id=%s, skipping", user["id"])
                failed += 1
                continue
            #
            if user.get("suspended") and personal_project.get("suspended"):
                log.info("Already suspended, skipping: user_id=%s", user["id"])
                skipped += 1
                continue
            #
            if dry_run:
                log.info(
                    "[DRY RUN] Would suspend user_id=%s (email=%s) and personal project_id=%s",
                    user["id"], user.get("email"), personal_project_id,
                )
                continue
            #
            try:
                with db.with_project_schema_session(None) as session:
                    db_project = session.query(Project).where(Project.id == personal_project_id).first()
                    if db_project:
                        db_project.suspended = True
                        session.commit()
                auth.update_user(id_=user["id"], suspended=True)
                log.info(
                    "Suspended user_id=%s and personal project_id=%s", user["id"], personal_project_id,
                )
                suspended += 1
            except Exception as exc:  # pylint: disable=W0703
                log.exception("Failed to suspend user_id=%s: %s", user["id"], exc)
                failed += 1
    #
    log.info(
        "Finished suspend_projects_and_users: processed=%s suspended=%s skipped=%s failed=%s dry_run=%s",
        processed, suspended, skipped, failed, dry_run,
    )


def delete_users_with_private_projects_cascade(*args, **kwargs):  # pylint: disable=W0613,R0912,R0914
    """
        Permanently delete users, their personal project, and system user record, in cascade.
        Param: JSON object, e.g. {"user_emails": ["a@x.com"], "dry_run": false, "confirm": true}.
        Requires user_ids or user_emails (bulk delete-all is not supported). dry_run defaults to true.
        Live execution (dry_run=false) also requires confirm=true. Irreversible.
    """
    from plugins.projects.api.v2.project import delete_project  # pylint: disable=E0401,C0415
    from tools import this  # pylint: disable=E0401,C0415
    #
    try:
        params = parse_param(kwargs.get("param", ""))
    except (json.JSONDecodeError, ValueError) as exc:
        log.error("Invalid param: %s", exc)
        return
    #
    user_ids = _to_list(params.get("user_ids"))
    user_emails = _to_list(params.get("user_emails"))
    dry_run = _to_bool(params.get("dry_run"), default=True)
    confirm = _to_bool(params.get("confirm"), default=False)
    #
    if not user_ids and not user_emails:
        log.error("At least one of user_ids/user_emails is required (bulk delete-all is not supported)")
        return
    #
    if not dry_run and not confirm:
        log.error("Live execution (dry_run=false) requires confirm=true; aborting without changes")
        return
    #
    users, missing = _resolve_users(user_ids, user_emails)
    #
    processed = deleted = skipped = failed = 0
    #
    for entry in missing:
        log.error("User not found, skipping: %s", entry)
        failed += 1
    #
    log.info("Starting delete_users_with_private_projects_cascade: dry_run=%s users=%s", dry_run, len(users))
    #
    for user in users:
        processed += 1
        user_id = int(user["id"])
        #
        if is_protected_user(user, executing_user_id=kwargs.get("_user_id")):
            log.info("Skipping protected user: id=%s email=%s", user_id, user.get("email"))
            skipped += 1
            continue
        #
        try:
            personal_project_id = context.rpc_manager.call.projects_get_personal_project_id(user_id)
            personal_project = (
                context.rpc_manager.call.project_get_by_id(personal_project_id)
                if personal_project_id else None
            )
            #
            all_project_ids = [
                int(project["id"])
                for project in context.rpc_manager.timeout(120).project_list(filter_={"create_success": True})
            ]
            team_project_ids = context.rpc_manager.call.admin_check_user_in_projects(all_project_ids, user_id)
            team_project_ids = [pid for pid in team_project_ids if pid != personal_project_id]
            #
            if dry_run:
                log.info(
                    "[DRY RUN] Would delete user_id=%s (email=%s), personal project_id=%s, "
                    "and remove memberships from team projects=%s",
                    user_id, user.get("email"), personal_project_id, team_project_ids,
                )
                continue
            #
            for team_project_id in team_project_ids:
                log.info("Removing user_id=%s from team project_id=%s", user_id, team_project_id)
                context.rpc_manager.call.admin_remove_users_from_project(team_project_id, [user_id])
            #
            if personal_project_id and personal_project:
                log.info("Deleting personal project_id=%s for user_id=%s", personal_project_id, user_id)
                delete_project(
                    project_id=personal_project_id,
                    module=this.for_module("projects").module,
                )
            #
            log.info("Deleting user_id=%s", user_id)
            auth.delete_user(user_id)
            #
            deleted += 1
        except Exception as exc:  # pylint: disable=W0703
            log.exception("Failed to delete user_id=%s: %s", user_id, exc)
            failed += 1
    #
    log.info(
        "Finished delete_users_with_private_projects_cascade: processed=%s deleted=%s skipped=%s failed=%s dry_run=%s",
        processed, deleted, skipped, failed, dry_run,
    )
