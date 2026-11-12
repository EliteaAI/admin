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

""" RPC — project restore jobs """

from pylon.core.tools import web  # pylint: disable=E0611,E0401


class RPC:  # pylint: disable=R0903

    @web.rpc("admin_project_restore_jobs_reap", "project_restore_jobs_reap")
    def project_restore_jobs_reap(self):
        """Fail restore jobs whose process stopped, delete finished ones older than 7 days."""
        return self.restore_jobs_reap()
