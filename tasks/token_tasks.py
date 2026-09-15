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


def migrate_user_system_tokens(*args, **kwargs):
    """Give every user without one a non-expiring system access token. Param: 'dry_run'. Safe to re-run."""
    #
    with make_logger() as log:
        log.info("Starting")
        start_ts = time.time()
        #
        try:
            dry_run = "dry_run" in kwargs.get("param", "")
            #
            log.info("Backfilling user system tokens (dry_run=%s)", dry_run)
            #
            # The statement lives in auth_core so the write stays on the side
            # that owns auth_core__token. Guarded by NOT EXISTS on
            # (user_id, name), so a re-run inserts nothing.
            result = context.rpc_manager.timeout(300).auth_backfill_system_tokens(
                dry_run=dry_run,
            )
            #
            log.info(
                "Users: %s total, %s already had a token, %s created, %s adopted",
                result["users_total"],
                result["already_present"],
                result["created"],
                result["squatters_adopted"],
            )
        except:  # pylint: disable=W0702
            log.exception("Got exception, stopping task (on timeout RPC will continue)")
        #
        end_ts = time.time()
        log.info("Exiting (duration = %s)", end_ts - start_ts)
