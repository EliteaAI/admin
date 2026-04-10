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
import json

from flask import request

try:
    from pydantic.v1 import ValidationError
except:  # pylint: disable=W0702
    from pydantic import ValidationError

from pylon.core.tools import log  # pylint: disable=E0611,E0401,W0611
from tools import auth, api_tools  # pylint: disable=E0401

from ...models.pd.user_input_field import UserInputFieldPD


class AdminAPI(api_tools.APIModeHandler):
    pass


class ProjectAPI(api_tools.APIModeHandler):
    pass


class API(api_tools.APIBase):  # pylint: disable=R0903
    url_params = [
        '<int:project_id>',
        '<string:mode>/<int:project_id>'
    ]
    mode_handlers = {
        'default': ProjectAPI,
        'administration': AdminAPI,
    }

    @auth.decorators.check_api({
        "permissions": ["configuration.users.users.view"],
        "recommended_roles": {
            "administration": {"admin": True, "viewer": False, "editor": False},
            "default": {"admin": True, "viewer": True, "editor": False},
            "developer": {"admin": True, "viewer": False, "editor": False},
        }})
    def get(self, project_id: int, **kwargs):
        project_users = self.module.get_users_roles_in_project(project_id, filter_system_user=True)
        user_ids = set(project_users.keys())
        all_users = auth.list_users(user_ids=user_ids)

        try:
            social_data: list = self.module.context.rpc_manager.call.social_get_users(user_ids)
        except KeyError:
            social_data = []

        avatar_map = {i['user_id']: i.get('avatar') for i in social_data}

        for user in all_users:
            roles = project_users.pop(user['id'], [])
            user['roles'] = roles
            if user['last_login']:
                user['last_login'] = user['last_login'].isoformat(timespec='seconds')
            avatar = avatar_map.pop(user['id'], None)
            user['avatar'] = avatar

        result = all_users
        # #
        # limit = request.args.get("limit", None)
        # offset = request.args.get("offset", None)
        # #
        # if limit is not None and offset is not None:
        #     limit = int(limit)
        #     offset = int(offset)
        #     #
        #     result = all_users[offset:offset+limit]

        return {
            "total": len(all_users),
            "rows": result,
        }, 200

    @auth.decorators.check_api({
        "permissions": ["configuration.users.users.create"],
        "recommended_roles": {
            "administration": {"admin": True, "viewer": False, "editor": False},
            "default": {"admin": True, "viewer": False, "editor": False},
            "developer": {"admin": True, "viewer": False, "editor": False},
        }})
    def post(self, project_id: int, **kwargs):
        user_emails = request.json["emails"]
        user_roles = request.json["roles"]
        results = []
        for user_email in user_emails:
            try:
                UserInputFieldPD(user_email=user_email)
            except ValidationError as e:
                results.append({'msg': e.errors()[0]["msg"], 'status': 'error'})
                continue
            result = self.module.context.rpc_manager.call.add_user_to_project_or_create(
                user_email, project_id, user_roles)
            results.append(result)
        added_ids = set()
        # try:
        #     if invitation_integration := request.json.get('invitation_integration'):
        #         from tools import TaskManager
        #         try:
        #             invitation_integration = json.loads(
        #                 invitation_integration
        #                 .replace("'", '"')
        #                 .replace("None", "null")
        #             )
        #         except json.JSONDecodeError as exc:
        #             log.info(f"Invitation integration exception: {exc}")
        #             pass
        #         log.info(f"Invitation integration: {invitation_integration=} "
        #                  f"{type(invitation_integration)=}")
        #         base_integration = invitation_integration['smtp_integration']
        #         log.info(f"Base integration: {base_integration}")
        #         email_integration = self.module.context.rpc_manager.call.integrations_get_by_id(
        #             project_id=base_integration['project_id'],
        #             integration_id=base_integration['id'],
        #         )
        #         log.info(f"Sending invitation to {user_emails} with {email_integration}")
        #         recipients = []
        #         for i in results:
        #             if i['status'] == 'ok':
        #                 added_ids.add(i['id'])
        #                 recipients.append(i['email'])
        #             i['email_sent'] = i['status'] == 'ok'
        #         TaskManager(project_id=project_id).run_task([{
        #             'recipients': recipients,
        #             'subject': f'Invitation to a Centry project {project_id}',
        #             'template': invitation_integration['template'],
        #         }], email_integration.task_id)
        # except ImportError:
        #     ...
        self.module.context.event_manager.fire_event(
            "user_added_to_project", {'project_id': project_id, 'user_ids': added_ids},
        )
        return results, 200

    @auth.decorators.check_api({
        "permissions": ["configuration.users.users.edit"],
        "recommended_roles": {
            "administration": {"admin": True, "viewer": False, "editor": False},
            "default": {"admin": True, "viewer": False, "editor": False},
            "developer": {"admin": True, "viewer": False, "editor": False},
        }})
    def put(self, project_id: int, **kwargs):
        user_ids = request.json.get("ids", [])
        user_id = request.json.get("id")

        if user_id:
            if user_ids:
                return {'msg': 'You cannot pass both "id" and "ids" at the same time'}, 400
            user_ids.append(user_id)

        new_user_roles = request.json["roles"]
        result = self.module.context.rpc_manager.call.update_roles_for_user(
            project_id, user_ids, new_user_roles)
        return {'msg': f'roles updated' if result else 'something is wrong'}, 200

    @auth.decorators.check_api({
        "permissions": ["configuration.users.users.delete"],
        "recommended_roles": {
            "administration": {"admin": True, "viewer": False, "editor": False},
            "default": {"admin": True, "viewer": False, "editor": False},
            "developer": {"admin": True, "viewer": False, "editor": False},
        }})
    def delete(self, project_id: int, **kwargs):
        try:
            delete_ids = list(map(int, request.args["id[]"].split(',')))
        except TypeError:
            return 'IDs must be integers', 400
        self.module.remove_users_from_project(project_id, delete_ids)
        self.module.context.event_manager.fire_event(
            "user_removed_from_project", {'project_id': project_id, 'user_ids': delete_ids},
        )
        return {'msg': 'users successfully removed'}, 204
