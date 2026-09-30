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

import time

from tools import context  # pylint: disable=E0401

from .lifecycle_tasks import parse_param, _to_bool, _to_int
from .logs import make_logger

DRY_RUN_PARAM = "dry_run"


def is_dry_run(param):
    """Read the rehearsal flag as an exact token, or refuse to guess.

    A near miss - "dryrun", "not_dry_run" - is resolved neither way: the
    operator asked for something this task does not offer, and writing tokens
    on the strength of a typo is not the answer.
    """
    token = (param or "").strip().lower()
    #
    if not token:
        return False
    if token == DRY_RUN_PARAM:
        return True
    #
    raise ValueError(
        f"Unrecognized param {param!r}: pass {DRY_RUN_PARAM!r} to rehearse, "
        "or nothing at all to write",
    )


def migrate_user_system_tokens(*args, **kwargs):
    """Give every user without one a non-expiring system access token. Param: 'dry_run' or nothing. Safe to re-run."""
    #
    with make_logger() as log:
        log.info("Starting")
        start_ts = time.time()
        #
        try:
            dry_run = is_dry_run(kwargs.get("param"))
            #
            log.info("Backfilling user system tokens (dry_run=%s)", dry_run)
            #
            # The statement lives in auth_core so the write stays on the side
            # that owns auth_core__token. Every insert is guarded by the
            # one-per-user index, so a re-run inserts nothing.
            result = context.rpc_manager.timeout(300).auth_backfill_system_tokens(
                dry_run=dry_run,
            )
            #
            log.info(
                "Users: %s total, %s already had a token, %s suspended and skipped",
                result["users_total"],
                result["already_present"],
                result["skipped_suspended"],
            )
            #
            if dry_run:
                # "created" is 0 on a dry run and saying it out loud is the point:
                # an operator reading this log has to be able to tell a rehearsal
                # from the real thing.
                log.info(
                    "Dry run: %s user(s) would get a token, none written",
                    result["missing"],
                )
            else:
                log.info(
                    "Created %s token(s) of %s missing",
                    result["created"],
                    result["missing"],
                )
                #
                if result["created"] != result["missing"]:
                    # Provisioned by a login, or by a second run of this task,
                    # between the scan and the insert. Not an error.
                    log.info(
                        "%s user(s) were provisioned elsewhere mid-run",
                        result["missing"] - result["created"],
                    )
            #
            if result["reserved_name_conflicts"]:
                log.warning(
                    "%s token(s) hold the reserved name with an expiry; those "
                    "users are healed on next use, not here",
                    result["reserved_name_conflicts"],
                )
        except:  # pylint: disable=W0702
            # Re-raise: the operator has to be able to tell a backfill that did
            # nothing from one that ran. A release deployed on the strength of a
            # task that only looked successful leaves users without the
            # credential the platform now assumes they have. On an RPC timeout
            # the remote side keeps going, so re-run the task to confirm.
            log.exception("Got exception, stopping task")
            raise
        #
        finally:
            end_ts = time.time()
            log.info("Exiting (duration = %s)", end_ts - start_ts)


PRUNE_PARAMS = {"dry_run", "project_id", "limit", "pause_every", "pause_s"}


def prune_system_tokens(*args, **kwargs):  # pylint: disable=R0914,R0915
    """Prune rotated system-user 'api' tokens down to the Vault one plus the newest. Empty param = dry run; use dry_run=false to apply to ALL projects (add project_id=N to try one, limit=N to cap projects per run). Also: pause_every (50), pause_s (0.5). Safe to re-run."""
    from plugins.admin.utils import system_tokens  # pylint: disable=E0401,C0415
    #
    with make_logger() as log:
        log.info("Starting")
        start_ts = time.time()
        #
        try:
            params = parse_param(kwargs.get("param"))
            unknown = set(params) - PRUNE_PARAMS
            if unknown:
                raise ValueError(f"Unknown param(s): {sorted(unknown)}; allowed: {sorted(PRUNE_PARAMS)}")
            #
            dry_run = _to_bool(params.get("dry_run"), "dry_run", default=True)
            project_id = _to_int(params["project_id"], "project_id") if "project_id" in params else None
            limit = _to_int(params["limit"], "limit") if "limit" in params else None
            pause_every = max(_to_int(params.get("pause_every", 50), "pause_every"), 1)
            try:
                pause_s = float(params.get("pause_s", 0.5))
            except (TypeError, ValueError):
                raise ValueError(f"Invalid number for 'pause_s': {params.get('pause_s')!r}") from None
            #
            verb = "would delete" if dry_run else "deleted"
            log.info(
                "Pruning system tokens (dry_run=%s, project_id=%s, limit=%s, pause %ss every %s)",
                dry_run, project_id, limit, pause_s, pause_every,
            )
            stats = {"scanned": 0, "pruned": 0, "clean": 0, "no_user": 0, "failed": 0, "tokens": 0}
            #
            def _prune(label, user_id, vault_client):
                stats["scanned"] += 1
                try:
                    count = system_tokens.prune_user_tokens(user_id, vault_client, dry_run, log)
                except Exception as exc:  # pylint: disable=W0703
                    stats["failed"] += 1
                    log.warning("%s (user %s): failed: %s", label, user_id, exc)
                    return
                if count is None:
                    stats["clean"] += 1
                    return
                stats["pruned"] += 1
                stats["tokens"] += count
                log.info("%s (user %s): %s %s token(s)", label, user_id, verb, count)
                return count
            #
            if project_id is None:
                admin_user_id = system_tokens.admin_user_id()
                if admin_user_id is None:
                    log.warning("Admin system user not found, skipping admin space")
                else:
                    _prune("Admin space", admin_user_id, system_tokens.VaultClient())
            #
            project_ids = system_tokens.list_project_ids(project_id)
            log.info("Projects to scan: %s", len(project_ids))
            #
            projects_pruned = 0
            for idx, pid in enumerate(project_ids, 1):
                if limit is not None and projects_pruned >= limit:
                    log.info("Limit of %s pruned project(s) reached before project %s", limit, pid)
                    break
                user_id = system_tokens.project_user_id(pid)
                if user_id is None:
                    stats["no_user"] += 1
                else:
                    if _prune(f"Project {pid}", user_id, system_tokens.project_vault(pid)) is not None:
                        projects_pruned += 1
                if idx % pause_every == 0:
                    log.info("Progress: %s/%s projects, %s, %.1fs", idx, len(project_ids), stats, time.time() - start_ts)
                    time.sleep(pause_s)
            #
            log.info("Done: %s token(s) %s; %s", stats["tokens"], verb, stats)
        except:  # pylint: disable=W0702
            log.exception("Got exception, stopping task")
            raise
        #
        finally:
            end_ts = time.time()
            log.info("Exiting (duration = %s)", end_ts - start_ts)
