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

import codecs
import tempfile

import flask  # pylint: disable=E0401

from pylon.core.tools import log  # pylint: disable=E0611,E0401

from tools import auth, api_tools, register_openapi  # pylint: disable=E0401
from tools import context  # pylint: disable=E0401
from tools import constants as c  # pylint: disable=E0401

from ...utils.project_restore import (
    KIND_SAFE, KIND_PG_DUMP, HEADER_SCAN_BYTES,
    detect_artifact_kind, parse_header, restore_safe_backup, run_psql,
)


FULL_MODE_PERMISSION = "projects.projects.restore.full"

READ_CHUNK = 262144
TRUE_VALUES = ("1", "true", "yes", "on")


def _flag(name, default=False):
    raw = flask.request.form.get(name)
    if raw is None:
        raw = flask.request.args.get(name)
    if raw is None:
        return default
    return str(raw).strip().lower() in TRUE_VALUES


def _param(name):
    value = flask.request.form.get(name)
    if value is None:
        value = flask.request.args.get(name)
    return value or ""


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=R0903
    """ API """

    @register_openapi(
        name="Restore Project Backup",
        description="Restore a backup produced by the project backup endpoint into a "
                    "project schema. Upload the .sql file as multipart form field 'file'. "
                    "Without 'tables' the whole artifact is applied (full restore); with "
                    "'tables' only the listed tables are applied (partial restore). "
                    "Safe backups are applied statement by statement in one transaction; "
                    "raw pg_dump artifacts are piped to psql and require the "
                    "'projects.projects.restore.full' permission.",
        parameters=[
            {"name": "project_id", "in": "path", "schema": {"type": "integer"},
             "description": "Target project ID."},
            {"name": "tables", "in": "query", "schema": {"type": "string"},
             "description": "Comma-separated tables to restore. Empty means full restore."},
            {"name": "include_parents", "in": "query", "schema": {"type": "boolean"},
             "description": "Also restore the FK parents of the listed tables."},
            {"name": "truncate", "in": "query", "schema": {"type": "boolean"},
             "description": "Empty the in-scope tables first (TRUNCATE ... CASCADE) "
                            "instead of merging with ON CONFLICT DO NOTHING."},
            {"name": "dry_run", "in": "query", "schema": {"type": "boolean"},
             "description": "Execute inside a transaction and roll it back."},
            {"name": "allow_project_mismatch", "in": "query", "schema": {"type": "boolean"},
             "description": "Required when the artifact was taken from another project."},
        ],
    )
    @auth.decorators.check_api({
        "permissions": ["projects.projects.restore.apply"],
        "recommended_roles": {
            "administration": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
            "default": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
            "developer": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
        }})
    def post(self, project_id: int, **kwargs):  # pylint: disable=R0911,R0914
        """ Process POST """
        _ = kwargs
        #
        if "file" not in flask.request.files:
            return {"ok": False, "error": "no file provided"}, 400
        #
        tables = [item.strip() for item in _param("tables").split(",") if item.strip()]
        include_parents = _flag("include_parents")
        truncate = _flag("truncate")
        dry_run = _flag("dry_run")
        allow_mismatch = _flag("allow_project_mismatch")
        #
        from tools import project_constants as pc  # pylint: disable=E0401,C0415
        schema = pc["PROJECT_SCHEMA_TEMPLATE"].format(project_id)
        #
        spool = tempfile.TemporaryFile()  # pylint: disable=R1732
        #
        try:
            source = flask.request.files["file"]
            filename = source.filename
            #
            while True:
                chunk = source.stream.read(READ_CHUNK)
                if not chunk:
                    break
                spool.write(chunk)
            #
            size = spool.tell()
            if not size:
                return {"ok": False, "error": "empty file"}, 400
            #
            spool.seek(0)
            head = spool.read(HEADER_SCAN_BYTES).decode("utf-8", "replace")
            #
            kind = detect_artifact_kind(head)
            if kind is None:
                return {"ok": False, "error": "unrecognized backup file"}, 400
            #
            artifact = parse_header(head)
            artifact["kind"] = kind
            artifact["filename"] = filename
            artifact["size"] = size
            #
            source_project = artifact.get("project_id")
            if isinstance(source_project, int) and source_project != project_id \
                    and not allow_mismatch:
                return {
                    "ok": False,
                    "error": "artifact belongs to project {}; pass "
                             "allow_project_mismatch=true to restore it into project {}".format(
                                 source_project, project_id),
                    "artifact": artifact,
                }, 409
            #
            if kind == KIND_PG_DUMP:
                current_permissions = auth.resolve_permissions(mode="administration")
                if not auth.has_access(current_permissions, [FULL_MODE_PERMISSION]):
                    return {"ok": False, "error": "access_denied"}, 403
                if tables:
                    return {
                        "ok": False,
                        "error": "partial restore is not supported for pg_dump artifacts",
                    }, 400
            #
            connection = context.db.engine.raw_connection()
            #
            try:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "select 1 from information_schema.schemata where schema_name = %s",
                        (schema,),
                    )
                    if cursor.fetchone() is None:
                        return {"ok": False, "error": "project schema not found"}, 404
                connection.rollback()
                #
                log.info(
                    "project_restore: applying %s artifact to %s (%s, dry_run=%s)",
                    kind, schema, "partial" if tables else "full", dry_run,
                )
                #
                if kind == KIND_SAFE:
                    result = restore_safe_backup(
                        connection,
                        open_chunks=self._text_chunks(spool),
                        schema=schema,
                        tables=tables,
                        include_parents=include_parents,
                        truncate=truncate,
                        dry_run=dry_run,
                    )
                else:
                    result = run_psql(
                        open_chunks=self._byte_chunks(spool),
                        schema=schema,
                        host=c.POSTGRES_HOST,
                        port=c.POSTGRES_PORT,
                        user=c.POSTGRES_USER,
                        password=c.POSTGRES_PASSWORD,
                        database=c.POSTGRES_DB,
                        dry_run=dry_run,
                    )
                    if result["return_code"] != 0 and not dry_run:
                        return {"ok": False, "error": "psql failed",
                                "artifact": artifact, "result": result}, 400
            finally:
                connection.close()
        except ValueError as exc:
            log.warning("project_restore: rejected artifact for %s: %s", schema, exc)
            return {"ok": False, "error": str(exc)}, 400
        except Exception as exc:  # pylint: disable=W0703
            log.exception("project_restore: failed for %s", schema)
            return {"ok": False, "error": "restore failed", "detail": str(exc)}, 500
        finally:
            spool.close()
        #
        result["mode"] = "partial" if tables else "full"
        return {"ok": True, "artifact": artifact, "result": result}, 200

    @staticmethod
    def _byte_chunks(spool):
        """ Re-readable byte stream over the uploaded file """
        def opener():
            spool.seek(0)
            while True:
                chunk = spool.read(READ_CHUNK)
                if not chunk:
                    break
                yield chunk
        #
        return opener

    @staticmethod
    def _text_chunks(spool):
        """ Re-readable text stream, decoded across chunk boundaries """
        def opener():
            spool.seek(0)
            decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
            while True:
                chunk = spool.read(READ_CHUNK)
                if not chunk:
                    break
                text = decoder.decode(chunk)
                if text:
                    yield text
            tail = decoder.decode(b"", True)
            if tail:
                yield tail
        #
        return opener


class API(api_tools.APIBase):  # pylint: disable=R0903
    """ API """

    url_params = [
        "<string:mode>/<int:project_id>",
    ]

    mode_handlers = {
        'administration': AdminAPI,
    }
