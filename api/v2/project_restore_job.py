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

""" API """

from tools import auth, api_tools, register_openapi  # pylint: disable=E0401

from ...utils import restore_jobs
from .project_restore import (
    PROMPT_LIB_MODE, PROJECT_BACKUP_PERMISSION, PROJECT_RESTORE_PERMISSION,
    _is_own_personal_project, job_status,
)


JOB_PARAMETERS = [
    {"name": "project_id", "in": "path", "schema": {"type": "integer"},
     "description": "Target project ID."},
    {"name": "job_id", "in": "path", "schema": {"type": "string"},
     "description": "Job ID returned when the restore was started."},
]


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=R0903
    """ API """

    @register_openapi(
        name="Get Project Restore Job",
        description="Status of a restore started with the project restore endpoint: "
                    "queued, running, done (with the restore summary) or failed (with "
                    "the error).",
        parameters=JOB_PARAMETERS,
    )
    @auth.decorators.check_api({
        "permissions": ["projects.projects.restore.apply"],
        "recommended_roles": {
            "administration": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
            "default": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
        }})
    def get(self, project_id: int, job_id: str, **kwargs):
        """ Process GET """
        _ = kwargs
        return job_status(self.module, project_id, job_id)


class PromptLibAPI(api_tools.APIModeHandler):  # pylint: disable=R0903
    """ API """

    @register_openapi(
        name="Get Project Restore Job (project scope)",
        description="Status of a restore started in this project: queued, running, done "
                    "(with the restore summary) or failed (with the error).",
        parameters=JOB_PARAMETERS,
    )
    @auth.decorators.check_api({
        "permissions": [PROJECT_BACKUP_PERMISSION],
        "recommended_roles": {
            "administration": {"super_admin": True, "admin": True, "viewer": False, "editor": True},
            "default": {"super_admin": True, "admin": True, "viewer": False, "editor": True},
        }})
    def get(self, project_id: int, job_id: str, **kwargs):
        """ Process GET """
        _ = kwargs
        # Whoever started the job may follow it; the permission (and the RPC
        # behind the personal project check) is only needed for other users
        job = self.module.restore_job_store().get(job_id, project_id=project_id)
        current_user = auth.current_user()
        if job is not None and current_user and job["user_id"] == current_user.get("id"):
            return restore_jobs.public_view(job), 200
        current_permissions = auth.resolve_permissions(
            mode=PROMPT_LIB_MODE, project_id=project_id,
        )
        if not auth.has_access(current_permissions, [PROJECT_RESTORE_PERMISSION]) \
                and not _is_own_personal_project(project_id):
            return {"ok": False, "error": "access_denied",
                    "required": [PROJECT_RESTORE_PERMISSION]}, 403
        return job_status(self.module, project_id, job_id)


class API(api_tools.APIBase):  # pylint: disable=R0903
    """ API """

    url_params = [
        "<string:mode>/<int:project_id>/<string:job_id>",
    ]

    mode_handlers = {
        'administration': AdminAPI,
        PROMPT_LIB_MODE: PromptLibAPI,
    }
