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

from .lifecycle_tasks import parse_param, _to_bool
from .logs import make_logger

# Exact strings no code checks: legacy theme section nodes, prefix-only rows, removed features.
DEAD_PERMISSIONS = (
    "admin",
    "configuration",
    "configuration.evaluation",
    "configuration.evaluation.platform_dimensions",
    "configurations",
    "invites",
    "invites.platform",
    "migration",
    "models.chat.conversations.list_custom",
    "modes",
    "projects",
    "projects.projects.backup",
    "projects.projects.restore",
    "runtime",
    "models.prompt_lib.approve_collection.post",
    "models.prompt_lib.collection.delete",
    "models.prompt_lib.collection.details",
    "models.prompt_lib.collection.update",
    "models.prompt_lib.collections.create",
    "models.prompt_lib.collections.list",
    "models.prompt_lib.public_collection.details",
    "models.prompt_lib.reject_collection.delete",
    "models.promptlib_shared.approve_collection.post",
    "models.promptlib_shared.collection.delete",
    "models.promptlib_shared.collection.details",
    "models.promptlib_shared.collection.update",
    "models.promptlib_shared.collections.create",
    "models.promptlib_shared.collections.list",
    "models.promptlib_shared.public_collection.details",
    "models.promptlib_shared.reject_collection.delete",
)

CLEANUP_PARAMS = {"dry_run"}


def cleanup_dead_permissions(*args, **kwargs):
    """Delete permission strings no code checks from all role/project/group/user grants. Empty param = dry run; dry_run=false to apply. Run after every upgrade, fresh installs included. Safe to re-run."""
    with make_logger() as log:
        log.info("Starting")
        start_ts = time.time()
        #
        try:
            params = parse_param(kwargs.get("param"))
            unknown = set(params) - CLEANUP_PARAMS
            if unknown:
                raise ValueError(f"Unknown param(s): {sorted(unknown)}; allowed: {sorted(CLEANUP_PARAMS)}")
            dry_run = _to_bool(params.get("dry_run"), "dry_run", default=True)
            #
            log.info("Cleaning %s dead permission string(s) (dry_run=%s)", len(DEAD_PERMISSIONS), dry_run)
            for permission in DEAD_PERMISSIONS:
                log.info("  - %s", permission)
            result = context.rpc_manager.timeout(120).auth_delete_permissions_everywhere(
                permissions=list(DEAD_PERMISSIONS), dry_run=dry_run,
            )
            #
            verb = "would delete" if dry_run else "deleted"
            for table, count in result["deleted"].items():
                log.info("%s: %s %s row(s)", table, verb, count)
            if dry_run:
                log.info("Dry run: nothing written; re-run with dry_run=false to apply")
        except:  # pylint: disable=W0702
            log.exception("Got exception, stopping task")
            raise
        finally:
            log.info("Exiting (duration = %s)", time.time() - start_ts)
