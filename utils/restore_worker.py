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
fresh interpreter has neither. Everything the job needs - database and
storage settings, the master key - arrives as one JSON document on stdin, so
no secret is visible in the process arguments or environment.

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
    for name in ("chat_backup", "project_backup", "chat_restore", "project_restore",
                 "backup_crypto", "restore_jobs", "restore_runner"):
        spec = importlib.util.spec_from_file_location(
            "{}.{}".format(PACKAGE, name), os.path.join(UTILS_PATH, "{}.py".format(name)),
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
    return sys.modules["{}.restore_runner".format(PACKAGE)]


class AttachmentStorage:
    """ The part of the platform storage client a restore uses, over plain boto3

    Bucket names carry the project prefix the platform client adds.
    """

    def __init__(self, settings):
        import boto3  # pylint: disable=E0401,C0415
        from botocore.client import Config  # pylint: disable=E0401,C0415
        #
        self.prefix = "p--{}.".format(settings["project_id"])
        self.region = settings.get("region")
        self.s3 = boto3.client(
            "s3", endpoint_url=settings.get("url"),
            aws_access_key_id=settings.get("access_key"),
            aws_secret_access_key=settings.get("secret_key"),
            config=Config(signature_version="s3v4"), region_name=self.region,
        )

    def _name(self, bucket):
        return bucket if bucket.startswith(self.prefix) else self.prefix + bucket

    def list_bucket(self):
        return [
            item["Name"][len(self.prefix):] for item in self.s3.list_buckets().get("Buckets", [])
            if item["Name"].startswith(self.prefix)
        ]

    def create_bucket(self, bucket, bucket_type=None, retention_days=None):
        name = self._name(bucket)
        self.s3.create_bucket(
            ACL="public-read", Bucket=name,
            CreateBucketConfiguration={"LocationConstraint": self.region},
        )
        if bucket_type:
            self.s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "type", "Value": bucket_type}]})
        if retention_days:
            self.s3.put_bucket_lifecycle_configuration(Bucket=name, LifecycleConfiguration={"Rules": [{
                "Expiration": {"Days": retention_days},
                "NoncurrentVersionExpiration": {"NoncurrentDays": retention_days},
                "ID": "bucket-retention-policy", "Filter": {"Prefix": ""}, "Status": "Enabled",
            }]})

    def list_files(self, bucket):
        files = []
        token = None
        while True:
            kwargs = {"Bucket": self._name(bucket)}
            if token:
                kwargs["ContinuationToken"] = token
            response = self.s3.list_objects_v2(**kwargs)
            files.extend({"name": item["Key"], "size": item["Size"]} for item in response.get("Contents", []))
            token = response.get("NextContinuationToken")
            if not token:
                return files

    def upload_file(self, bucket, content, name):
        return self.s3.put_object(Key=name, Bucket=self._name(bucket), Body=content)

    def remove_file(self, bucket, name):
        return self.s3.delete_object(Key=name, Bucket=self._name(bucket))


def main():
    logging.basicConfig(
        level=logging.INFO, stream=sys.stderr,
        format="%(asctime)s - %(levelname)8s - project_restore_worker - %(message)s",
    )
    payload = json.loads(sys.stdin.read())
    master_key = payload.get("master_key")
    _install_stand_ins(master_key)
    runner = _load_utils()
    #
    storage = AttachmentStorage(payload["storage"]) if payload.get("storage") else None
    status = runner.run_worker(payload, storage)
    sys.exit(status)


if __name__ == "__main__":
    main()
