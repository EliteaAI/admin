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
from pylon.core.tools import log  # pylint: disable=E0611,E0401,W0611

from tools import auth  # pylint: disable=E0401
from tools import api_tools  # pylint: disable=E0401
from tools import context, rpc_tools, db  # pylint: disable=E0401


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=R0903
    """ API """
    @auth.decorators.check_api(["migration.db"])
    def post(self):  # pylint: disable=R0912,R0914
        """ Process POST """
        version_model_class_to_entity_id_mapper = {
            rpc_tools.RpcMixin().rpc.call.prompt_lib_get_version_model(): "prompt_id",
            rpc_tools.RpcMixin().rpc.call.applications_get_version_model(): "application_id"
        }

        project_list = rpc_tools.RpcMixin().rpc.call.project_list(
            filter_={'create_success': True}
        )

        try:
            for project in project_list:
                with db.get_session(project['id']) as session:
                    for version_class, attribute_name in version_model_class_to_entity_id_mapper.items():
                        versions = session.query(version_class).all()
                        for version in versions:
                            version_meta = version.meta

                            if not version_meta:
                                continue

                            log.debug(f'{version_meta=}')

                            source_version_parent_entity_id = version_meta.get('parent_entity_id')
                            source_version_parent_project_id = version_meta.get('parent_project_id')
                            source_version_parent_entity_version_id = version_meta.get('parent_entity_version_id')

                            if source_version_parent_project_id and source_version_parent_entity_id and not source_version_parent_entity_version_id:
                                with db.get_session(source_version_parent_project_id) as parent_session:
                                    source_versions = parent_session.query(version_class).filter(
                                        getattr(version_class, attribute_name) == source_version_parent_entity_id
                                    ).all()

                                    for source_version in source_versions:
                                        if source_version.name == version.name:
                                            new_version_meta = {
                                                **version.meta,
                                                'parent_entity_version_id': source_version.id,
                                            }
                                            log.debug(f'New meta {new_version_meta=}')
                                            version.meta = new_version_meta
                                            session.commit()
        except Exception as e:
            log.debug(e)

        return {
            "ok": True
        }


class API(api_tools.APIBase):  # pylint: disable=R0903
    """ API """

    url_params = [
        "<string:mode>",
    ]

    mode_handlers = {
        'administration': AdminAPI,
    }
