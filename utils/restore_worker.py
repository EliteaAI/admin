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

""" Project restore worker: a fresh interpreter applying one restore job

Started by restore_runner with `python -I restore_worker.py`. A fork of the
gevent web process inherits its hub and listener threads and can stall; a
fresh interpreter has neither. Everything the job needs - database settings,
the master key - arrives as the first JSON line on stdin, so no secret is
visible in the process arguments or environment. Files go to storage through
the pylon that started the worker (restore_storage): stdout carries the
storage calls, stdin their replies, so the worker keeps stdout for that alone.

The worker imports the restore utils as a package of their own, with a
minimal stand-in for the pylon modules they import.
"""

import importlib.util
import json
import logging
import os
import sys
import types


UTILS_PATH = os.path.dirname(os.path.abspath(__file__))
SHARED_TOOLS_PATH = os.path.join(os.path.dirname(os.path.dirname(UTILS_PATH)), "shared", "tools")
PACKAGE = "restore_worker_utils"

log = logging.getLogger("project_restore_worker")


def _install_stand_ins(master_key):
    """ pylon.core.tools.log and tools.{artifact_crypto,config} for the utils """
    pylon_tools = types.ModuleType("pylon.core.tools")
    pylon_tools.log = log
    sys.modules.setdefault("pylon", types.ModuleType("pylon"))
    sys.modules.setdefault("pylon.core", types.ModuleType("pylon.core"))
    sys.modules["pylon.core.tools"] = pylon_tools
    #
    tools = types.ModuleType("tools")
    tools.config = types.SimpleNamespace(SECRETS_MASTER_KEY=master_key)
    sys.modules["tools"] = tools
    sys.modules["tools.config"] = tools.config
    #
    spec = importlib.util.spec_from_file_location(
        "tools.artifact_crypto", os.path.join(SHARED_TOOLS_PATH, "artifact_crypto.py"),
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    tools.artifact_crypto = module


def _load_utils():
    package = types.ModuleType(PACKAGE)
    package.__path__ = [UTILS_PATH]
    sys.modules[PACKAGE] = package
    for name in ("skill_files_backup", "chat_backup", "project_backup", "chat_restore", "project_restore",
                 "backup_crypto", "restore_jobs", "restore_storage", "restore_runner"):
        spec = importlib.util.spec_from_file_location(
            "{}.{}".format(PACKAGE, name), os.path.join(UTILS_PATH, "{}.py".format(name)),
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
    return sys.modules["{}.restore_runner".format(PACKAGE)]


def main():
    logging.basicConfig(
        level=logging.INFO, stream=sys.stderr,
        format="%(asctime)s - %(levelname)8s - project_restore_worker - %(message)s",
    )
    payload = json.loads(sys.stdin.readline())
    master_key = payload.get("master_key")
    _install_stand_ins(master_key)
    runner = _load_utils()
    #
    # Nothing else may write to stdout: it is the storage channel
    channel, sys.stdout = sys.stdout, sys.stderr
    storage = sys.modules["{}.restore_storage".format(PACKAGE)].StorageProxy(channel, sys.stdin) \
        if payload.get("with_storage") else None
    status = runner.run_worker(payload, storage)
    sys.exit(status)


if __name__ == "__main__":
    main()
