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

_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off"}


def _to_list(value):
    """ Coerce a scalar, comma-separated string, or list into a list """
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return [value]


def _to_bool(value, field_name, default=False):
    """ Strictly coerce a boolean-ish value; reject anything unrecognized """
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    normalized = str(value).strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise ValueError(f"Invalid boolean value for '{field_name}': {value!r}")


def _to_int(value, field_name):
    """ Coerce a value to int, raising a clear error on bad input """
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ValueError(f"Invalid integer value for '{field_name}': {value!r}") from None


def _to_int_list(value, field_name):
    """ Coerce a scalar/CSV-string/list into a list of ints """
    return [_to_int(item, field_name) for item in _to_list(value)]


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
        try:
            return json.loads(param)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in param: {exc}") from exc
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
    from plugins.projects.constants import PROJECT_PERSONAL_NAME_TEMPLATE  # pylint: disable=E0401,C0415
    #
    prefix = PROJECT_PERSONAL_NAME_TEMPLATE.split("{", 1)[0]
    return bool(project) and str(project.get("name", "")).startswith(prefix)


def is_protected_user(user, executing_user_id=None):
    """ Check whether a user must never be suspended/deleted by these tasks """
    if not user:
        return True
    #
    from plugins.projects.rpc.poc import is_system_user  # pylint: disable=E0401,C0415
    #
    user_id = int(user["id"])
    if user_id == PROTECTED_USER_ID:
        return True
    if is_system_user(user.get("email", "")):
        return True
    if executing_user_id is not None and user_id == executing_user_id:
        return True
    return False


def is_protected_project(project, protected_project_ids):
    """ Check whether a project is a public/system project that must never be suspended/deleted """
    return bool(project) and int(project["id"]) in protected_project_ids


def _protected_project_ids():
    """ Best-effort resolution of public/system project ids (AI/public project, support project) """
    protected = set()
    try:
        from tools import elitea_config  # pylint: disable=E0401,C0415
        #
        protected.add(int(elitea_config.get("ai_project_id", 1)))
    except Exception:  # pylint: disable=W0703
        protected.add(1)
    #
    try:
        if "support_assistant" in context.module_manager.modules:
            support_config = context.rpc_manager.timeout(2).support_assistant_get_config()
            support_project_id = support_config.get("project_id") if support_config else None
            if support_project_id:
                protected.add(int(support_project_id))
    except Exception:  # pylint: disable=W0703
        pass
    #
    return protected


def _resolve_executing_user_id(raw):
    """ Best-effort int coercion of the executing admin's id (may be '-' for non-user auth) """
    if raw is None:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        log.warning("Could not resolve executing user id from: %r", raw)
        return None


def _resolve_users(user_ids, user_emails):
    """ Resolve a mixed list of user ids / emails into user dicts, reporting misses """
    resolved = {}
    missing = []
    #
    if user_ids:
        found = auth.list_users(user_ids=user_ids)
        found_ids = set()
        for user in found:
            user_id = int(user["id"])
            resolved[user_id] = user
            found_ids.add(user_id)
        for user_id in user_ids:
            if user_id not in found_ids:
                missing.append(f"user_id={user_id}")
    #
    for email in user_emails or []:
        try:
            user = auth.get_user(email=email)
        except RuntimeError:
            user = None
        if not user:
            missing.append(f"user_email={email}")
            continue
        resolved[int(user["id"])] = user
    #
    return list(resolved.values()), missing


def _resolve_projects(project_ids):
    """ Resolve a list of project ids into project dicts, reporting misses """
    resolved = []
    missing = []
    for project_id in project_ids:
        project = context.rpc_manager.call.project_get_by_id(project_id)
        if not project:
            missing.append(f"project_id={project_id}")
            continue
        resolved.append(project)
    return resolved, missing


def suspend_projects_and_users(*args, **kwargs):  # pylint: disable=W0613,R0912,R0914,R0915
    """
        Suspend private projects with their owners, or team projects only.
        Param: JSON object, e.g. {"scope": "team_projects", "project_ids": [1,2], "dry_run": true}.
        scope: 'private_with_users' (selectors: user_ids/user_emails/project_ids of personal
        projects) or 'team_projects' (project_ids only). Optional: "all": true, reason, dry_run
        (default true). Reason is recorded in task logs only. Destructive when dry_run=false.
    """
    from plugins.projects.models.project import Project  # pylint: disable=E0401,C0415
    from tools import db  # pylint: disable=E0401,C0415
    #
    params = parse_param(kwargs.get("param", ""))
    #
    scope = params.get("scope")
    if scope not in {"private_with_users", "team_projects"}:
        raise ValueError(
            f"Invalid or missing 'scope' (must be 'private_with_users' or 'team_projects'): {scope!r}"
        )
    #
    project_ids = _to_int_list(params.get("project_ids"), "project_ids")
    user_ids = _to_int_list(params.get("user_ids"), "user_ids")
    user_emails = _to_list(params.get("user_emails"))
    process_all = _to_bool(params.get("all"), "all", default=False)
    dry_run = _to_bool(params.get("dry_run"), "dry_run", default=True)
    reason = params.get("reason") or ""
    #
    if not process_all and not project_ids and not user_ids and not user_emails:
        raise ValueError(
            "At least one selector (project_ids/user_ids/user_emails) is required unless 'all' is true"
        )
    #
    executing_user_id = _resolve_executing_user_id(kwargs.get("_executing_user_id"))
    if not dry_run and executing_user_id is None:
        raise ValueError(
            "Could not identify the executing admin; refusing to run live without self-protection"
        )
    #
    protected_project_ids = _protected_project_ids()
    #
    processed = affected = skipped = failed = 0
    #
    log.info(
        "Starting suspend_projects_and_users: scope=%s dry_run=%s reason=%r", scope, dry_run, reason,
    )
    #
    if scope == "team_projects":
        if process_all:
            candidates = [
                project for project in context.rpc_manager.timeout(120).project_list(
                    filter_={"create_success": True},
                )
                if not is_personal_project(project)
            ]
        else:
            candidates, missing = _resolve_projects(project_ids)
            for entry in missing:
                log.info("Skipping (not found): %s", entry)
                processed += 1
                skipped += 1
        #
        for project in candidates:
            processed += 1
            #
            if is_personal_project(project):
                log.info("Skipping personal project under scope=team_projects: project_id=%s", project["id"])
                skipped += 1
                continue
            #
            if is_protected_project(project, protected_project_ids):
                log.info("Skipping protected (public/system) project_id=%s", project["id"])
                skipped += 1
                continue
            #
            if project.get("suspended"):
                log.info("Already suspended, skipping: project_id=%s", project["id"])
                skipped += 1
                continue
            #
            if dry_run:
                log.info(
                    "[DRY RUN] Would suspend team project_id=%s name=%s reason=%r",
                    project["id"], project.get("name"), reason,
                )
                affected += 1
                continue
            #
            try:
                with db.with_project_schema_session(None) as session:
                    db_project = session.query(Project).where(Project.id == project["id"]).first()
                    if not db_project:
                        raise RuntimeError(f"Project {project['id']} disappeared before suspension")
                    db_project.suspended = True
                    session.commit()
                log.info("Suspended team project_id=%s reason=%r", project["id"], reason)
                affected += 1
            except Exception:  # pylint: disable=W0703
                log.exception("Failed to suspend project_id=%s", project["id"])
                failed += 1
    #
    else:  # private_with_users
        users_by_id = {}
        missing_all = []
        #
        if process_all:
            for user in auth.list_users():
                users_by_id[int(user["id"])] = user
        else:
            if user_ids or user_emails:
                found_users, missing = _resolve_users(user_ids, user_emails)
                missing_all.extend(missing)
                for user in found_users:
                    users_by_id[int(user["id"])] = user
            #
            if project_ids:
                projects, missing = _resolve_projects(project_ids)
                missing_all.extend(missing)
                for project in projects:
                    if not is_personal_project(project):
                        log.info(
                            "Skipping non-personal project under scope=private_with_users: project_id=%s",
                            project["id"],
                        )
                        processed += 1
                        skipped += 1
                        continue
                    owner = (
                        auth.get_user(user_id=project["owner_id"])
                        if project.get("owner_id") else None
                    )
                    if owner:
                        users_by_id[int(owner["id"])] = owner
                    else:
                        missing_all.append(f"owner of project_id={project['id']}")
        #
        for entry in missing_all:
            log.info("Skipping (not found): %s", entry)
            processed += 1
            skipped += 1
        #
        for user in users_by_id.values():
            processed += 1
            #
            if is_protected_user(user, executing_user_id=executing_user_id):
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
                log.info("No personal project found for user_id=%s, skipping", user["id"])
                skipped += 1
                continue
            #
            if is_protected_project(personal_project, protected_project_ids):
                log.info("Skipping protected (public/system) project for user_id=%s", user["id"])
                skipped += 1
                continue
            #
            user_suspended = bool(user.get("suspended"))
            project_suspended = bool(personal_project.get("suspended"))
            #
            if user_suspended and project_suspended:
                log.info("Already suspended, skipping: user_id=%s", user["id"])
                skipped += 1
                continue
            #
            if dry_run:
                log.info(
                    "[DRY RUN] Would suspend user_id=%s (email=%s) and personal project_id=%s reason=%r",
                    user["id"], user.get("email"), personal_project_id, reason,
                )
                affected += 1
                continue
            #
            try:
                if not project_suspended:
                    with db.with_project_schema_session(None) as session:
                        db_project = session.query(Project).where(
                            Project.id == personal_project_id,
                        ).first()
                        if not db_project:
                            raise RuntimeError(
                                f"Personal project {personal_project_id} disappeared before suspension"
                            )
                        db_project.suspended = True
                        session.commit()
                if not user_suspended:
                    auth.update_user(id_=user["id"], suspended=True)
                log.info(
                    "Suspended user_id=%s and personal project_id=%s reason=%r",
                    user["id"], personal_project_id, reason,
                )
                affected += 1
            except Exception:  # pylint: disable=W0703
                log.exception("Failed to suspend user_id=%s", user["id"])
                failed += 1
    #
    log.info(
        "Finished suspend_projects_and_users: processed=%s affected=%s skipped=%s failed=%s dry_run=%s",
        processed, affected, skipped, failed, dry_run,
    )


def delete_users_with_private_projects_cascade(*args, **kwargs):  # pylint: disable=W0613,R0912,R0914
    """
        Permanently delete users, their personal project, and system user record, in cascade.
        Param: JSON object, e.g. {"user_emails": ["a@x.com"], "dry_run": false, "confirm": true}.
        Requires user_ids or user_emails (bulk delete-all is not supported). Users who own a team
        project, or protected/system/executing-admin users, are skipped rather than orphaning
        ownership. dry_run defaults to true; live execution (dry_run=false) also requires
        confirm=true. Irreversible.
    """
    from plugins.projects.api.v2.project import delete_project  # pylint: disable=E0401,C0415
    from tools import this  # pylint: disable=E0401,C0415
    #
    params = parse_param(kwargs.get("param", ""))
    #
    user_ids = _to_int_list(params.get("user_ids"), "user_ids")
    user_emails = _to_list(params.get("user_emails"))
    dry_run = _to_bool(params.get("dry_run"), "dry_run", default=True)
    confirm = _to_bool(params.get("confirm"), "confirm", default=False)
    #
    if not user_ids and not user_emails:
        raise ValueError("At least one of user_ids/user_emails is required (bulk delete-all is not supported)")
    #
    if not dry_run and not confirm:
        raise ValueError("Live execution (dry_run=false) requires confirm=true; aborting without changes")
    #
    executing_user_id = _resolve_executing_user_id(kwargs.get("_executing_user_id"))
    if not dry_run and executing_user_id is None:
        raise ValueError(
            "Could not identify the executing admin; refusing to run live without self-protection"
        )
    #
    protected_project_ids = _protected_project_ids()
    #
    users, missing = _resolve_users(user_ids, user_emails)
    #
    processed = deleted = skipped = failed = 0
    #
    for entry in missing:
        log.info("Skipping (not found): %s", entry)
        processed += 1
        skipped += 1
    #
    log.info("Starting delete_users_with_private_projects_cascade: dry_run=%s users=%s", dry_run, len(users))
    #
    all_projects = context.rpc_manager.timeout(120).project_list(filter_={"create_success": True})
    all_project_ids = [int(project["id"]) for project in all_projects]
    #
    team_project_ids_by_owner = {}
    for project in all_projects:
        if not is_personal_project(project):
            team_project_ids_by_owner.setdefault(int(project["owner_id"]), []).append(int(project["id"]))
    #
    for user in users:
        processed += 1
        user_id = int(user["id"])
        #
        if is_protected_user(user, executing_user_id=executing_user_id):
            log.info("Skipping protected user: id=%s email=%s", user_id, user.get("email"))
            skipped += 1
            continue
        #
        owned_team_project_ids = team_project_ids_by_owner.get(user_id)
        if owned_team_project_ids:
            log.info(
                "Skipping user_id=%s: owns team project(s) %s, cascade would orphan ownership",
                user_id, owned_team_project_ids,
            )
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
            if personal_project and is_protected_project(personal_project, protected_project_ids):
                log.info("Skipping protected (public/system) personal project for user_id=%s", user_id)
                skipped += 1
                continue
            #
            team_project_ids = context.rpc_manager.call.admin_check_user_in_projects(all_project_ids, user_id)
            team_project_ids = [pid for pid in team_project_ids if pid != personal_project_id]
            #
            if dry_run:
                log.info(
                    "[DRY RUN] Would delete user_id=%s (email=%s), personal project_id=%s, "
                    "and remove memberships from team projects=%s",
                    user_id, user.get("email"), personal_project_id, team_project_ids,
                )
                deleted += 1
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
        except Exception:  # pylint: disable=W0703
            log.exception("Failed to delete user_id=%s", user_id)
            failed += 1
    #
    log.info(
        "Finished delete_users_with_private_projects_cascade: processed=%s deleted=%s skipped=%s failed=%s dry_run=%s",
        processed, deleted, skipped, failed, dry_run,
    )
