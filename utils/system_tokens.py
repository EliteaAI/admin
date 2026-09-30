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

""" Utils — system user 'api' token rotation and pruning """

import time

from pylon.core.tools import log  # pylint: disable=E0611,E0401

from tools import auth, context, VaultClient  # pylint: disable=E0401

ADMIN_SYSTEM_USER_EMAIL = "system@centry.user"
ROTATED_TOKEN_NAME = "api"


def admin_user_id():
    """ User id of the admin-space system user, or None """
    try:
        return auth.get_user(email=ADMIN_SYSTEM_USER_EMAIL)["id"]
    except Exception:  # pylint: disable=W0703
        return None


def project_user_id(project_id):
    """ User id of the project system user, or None """
    from plugins.projects.utils import get_project_user  # pylint: disable=E0401,C0415
    #
    try:
        user = get_project_user(project_id)
    except Exception:  # pylint: disable=W0703
        return None
    return None if user is None else user["id"]


def list_project_ids(project_id=None):
    """ Sorted ids of successfully created projects, optionally just one """
    projects = context.rpc_manager.timeout(120).project_list(
        filter_={"create_success": True},
    )
    ids = sorted(int(item["id"]) for item in projects)
    if project_id is not None:
        ids = [item for item in ids if item == project_id]
    return ids


def project_vault(project_id):
    """ VaultClient for a known project id """
    # A dict skips project_get_or_404, a DB lookup that spams "new local session" from task threads
    return VaultClient({"id": project_id})


def vault_token_id(secrets, user_id):
    """ Id of the token held in Vault secrets, only if it belongs to user_id """
    token = (secrets or {}).get("auth_token")
    if not token:
        return None
    try:
        data = auth.decode_token(token)
    except Exception:  # pylint: disable=W0703
        return None
    if not data or data.get("user_id") != user_id:
        return None
    return data.get("id")


def rotatable_tokens(user_id):
    """ Non-expiring 'api' tokens of the user: what rotation mints and may revoke """
    return [
        item for item in auth.list_tokens(user_id, name=ROTATED_TOKEN_NAME)
        if item.get("expires") is None
    ]


PROGRESS_EVERY = 1000


def prune_tokens(tokens, keep_ids, dry_run, task_log=None):
    """ Delete every token not in keep_ids; returns the (would-be) deleted count """
    deleted = 0
    for item in tokens:
        if item["id"] in keep_ids:
            continue
        if dry_run:
            deleted += 1
            continue
        deleted += auth.delete_token(item["id"]) or 0
        time.sleep(0)  # yield to the hub between single-row RPCs
        if task_log is not None and deleted % PROGRESS_EVERY == 0:
            task_log.info("  ... %s of %s token(s) deleted", deleted, len(tokens) - len(keep_ids))
    return deleted


def rotate_user_token(user_id, vault_client):
    """ Mint a new token into Vault, then revoke all older ones except the previous """
    snapshot = rotatable_tokens(user_id)
    secrets = vault_client.get_secrets()
    prev_id = vault_token_id(secrets, user_id) or max(
        (item["id"] for item in snapshot), default=None,
    )
    #
    token_id = auth.add_token(user_id, ROTATED_TOKEN_NAME)
    secrets["auth_token"] = auth.encode_token(token_id)
    vault_client.set_secrets(secrets)
    # Only pre-existing rows are pruned, so concurrently minted tokens survive
    return prune_tokens(snapshot, {prev_id}, dry_run=False)


def rotate_admin_token():
    """ Rotate the admin-space auth_token; returns revoked count or None """
    user_id = admin_user_id()
    if user_id is None:
        log.warning("Cannot rotate admin token: system user not found")
        return None
    revoked = rotate_user_token(user_id, VaultClient())
    log.info("Admin auth_token rotated, %s old token(s) revoked", revoked)
    return revoked


def rotate_project_tokens():
    """ Rotate auth_token of every project; one failing project does not stop the rest """
    stats = {"rotated": 0, "skipped": 0, "failed": 0, "revoked": 0}
    for project_id in list_project_ids():
        time.sleep(0)
        user_id = project_user_id(project_id)
        if user_id is None:
            log.warning("No system user for project %s, skipping", project_id)
            stats["skipped"] += 1
            continue
        try:
            stats["revoked"] += rotate_user_token(user_id, project_vault(project_id))
            stats["rotated"] += 1
        except Exception:  # pylint: disable=W0703
            log.exception("Failed to rotate auth_token of project %s", project_id)
            stats["failed"] += 1
    log.info("Project auth_token rotation done: %s", stats)
    return stats


def prune_user_tokens(user_id, vault_client, dry_run, task_log):
    """ Drop a user's backlog down to the Vault token plus the newest; None if already clean """
    tokens = rotatable_tokens(user_id)
    if len(tokens) <= 2:
        return None
    newest = sorted((item["id"] for item in tokens), reverse=True)
    vault_id = vault_token_id(vault_client.get_secrets(), user_id)
    if vault_id is None:
        task_log.warning(
            "User %s: Vault auth_token unresolvable, keeping newest 2 of %s", user_id, len(tokens),
        )
        keep_ids = set(newest[:2])
    else:
        keep_ids = {vault_id, newest[0]}
    return prune_tokens(tokens, keep_ids, dry_run, task_log)
