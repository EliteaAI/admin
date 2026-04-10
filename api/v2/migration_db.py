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

import flask  # pylint: disable=E0401,W0611
import psycopg2  # pylint: disable=E0401,W0611

from pylon.core.tools import log  # pylint: disable=E0611,E0401,W0611

from tools import auth  # pylint: disable=E0401
from tools import api_tools  # pylint: disable=E0401
from tools import context  # pylint: disable=E0401
from tools import constants as c  # pylint: disable=E0401


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=R0903
    """ API """

    @auth.decorators.check_api(["migration.db"])
    def post(self):  # pylint: disable=R0912,R0914
        """ Process POST """
        data = flask.request.get_json()
        #
        sqls = data.get("sqls", "").strip()
        exceptions = data.get("exceptions", "").strip()
        #
        logs = []
        #
        cmds = sqls.splitlines()
        except_pids = set()
        handled_exceptions = []
        #
        if not exceptions:
            handled_exceptions.append(psycopg2.errors.InvalidSchemaName)
        else:
            for item in exceptions.split(","):
                handled_exceptions.append(getattr(psycopg2.errors, item.strip()))
        #
        def get_projects(connection):
            with connection.cursor() as cur:
                cur.execute(f'select id from {c.POSTGRES_SCHEMA}."project";')
                result = cur.fetchall()
                return set(i[0] for i in result)
        #
        connection = context.db.engine.raw_connection()
        try:
            from tools import project_constants as pc  # pylint: disable=E0401,C0415
            #
            project_ids = get_projects(connection)
            final_project_ids = set(project_ids).difference(set(except_pids))
            #
            with connection.cursor() as cur:
                for project_id in final_project_ids:
                    pid = pc["PROJECT_SCHEMA_TEMPLATE"].format(project_id)
                    #
                    logs.append(f"Processing project {project_id}: {pid}")
                    #
                    for cmd in cmds:
                        exec_cmd = cmd.format(pid=pid)
                        try:
                            cur.execute(exec_cmd)
                            connection.commit()
                            #
                            logs.append(f"\t{exec_cmd}")
                        except tuple(handled_exceptions) as exc:
                            connection.rollback()
                            #
                            logs.append(f"\t{exec_cmd}\t\t-FAIL(handled)-{str(exc).strip()}")
                        except Exception as exc:
                            log.error(f"Unhandled exception: {exc}")
        except:  # pylint: disable=W0702
            log.exception("Got exception")
            #
            return {
                "ok": False,
                "logs": "\n".join(logs),
            }
        finally:
            connection.close()
        #
        return {
            "ok": True,
            "logs": "\n".join(logs),
        }


class API(api_tools.APIBase):  # pylint: disable=R0903
    """ API """

    url_params = [
        "<string:mode>",
    ]

    mode_handlers = {
        'administration': AdminAPI,
    }
