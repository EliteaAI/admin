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

""" Storage of a restore worker, served by the pylon that started it

The worker can not build the platform storage client: it needs RPC, the
plugin config, the storage_meta table and the event manager of a running
pylon. So it asks the pylon over its pipes - one JSON line per call - and the
pylon runs the call on MinioClient, whatever storage engine is configured
(s3, libcloud, filesystem), with its usage events.

Only the calls a restore makes are served.
"""

import base64
import json


METHODS = ("list_bucket", "create_bucket", "list_files", "upload_file", "remove_file")


class StorageCallFailed(Exception):
    """ The pylon could not run a storage call """


class StorageProxy:
    """ Worker side: the restore's storage client, each call a request to the pylon """

    def __init__(self, requests, replies):
        self.requests = requests
        self.replies = replies

    def _call(self, method, *args, **kwargs):
        # Positional as the restore code calls them: the platform's space_monitor reads args
        args = [{"b64": base64.b64encode(item).decode("ascii")} if isinstance(item, (bytes, bytearray)) else item
                for item in args]
        self.requests.write(json.dumps({"method": method, "args": args, "kwargs": kwargs}) + "\n")
        self.requests.flush()
        line = self.replies.readline()
        if not line:
            raise StorageCallFailed("the pylon closed the storage channel")
        reply = json.loads(line)
        if "error" in reply:
            raise StorageCallFailed(reply["error"])
        return reply.get("result")

    def list_bucket(self):
        return self._call("list_bucket")

    def create_bucket(self, bucket, bucket_type=None, retention_days=None):
        return self._call("create_bucket", bucket=bucket, bucket_type=bucket_type, retention_days=retention_days)

    def list_files(self, bucket):
        return self._call("list_files", bucket)

    def upload_file(self, bucket, file_obj, file_name):
        return self._call("upload_file", bucket, file_obj, file_name)

    def remove_file(self, bucket, file_name):
        return self._call("remove_file", bucket, file_name)


def _plain(value):
    """ A storage call result as JSON: S3 responses carry datetimes and other objects,
    which travel as text rather than being dropped """
    return json.loads(json.dumps(value, default=str))


def serve(open_client, requests, replies):
    """ Pylon side: run the worker's storage calls until it closes the channel

    open_client() builds the storage client on first use, so a restore that
    touches no file never asks RPC for the project.
    """
    client = None
    for line in requests:
        try:
            request = json.loads(line)
            method = request["method"]
            if method not in METHODS:
                raise ValueError("storage call not allowed: {}".format(method))
            args = [base64.b64decode(item["b64"]) if isinstance(item, dict) and "b64" in item else item
                    for item in request.get("args") or []]
            kwargs = dict(request.get("kwargs") or {})
            if client is None:
                client = open_client()
            reply = {"result": _plain(getattr(client, method)(*args, **kwargs))}
        except Exception as exc:  # pylint: disable=W0703
            reply = {"error": "{}: {}".format(type(exc).__name__, exc)}
        replies.write((json.dumps(reply) + "\n").encode("utf-8"))
        replies.flush()
