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
