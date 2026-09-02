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

import re
import datetime

import flask  # pylint: disable=E0401

from pylon.core.tools import log  # pylint: disable=E0611,E0401

from tools import auth, api_tools, register_openapi  # pylint: disable=E0401
from tools import context  # pylint: disable=E0401
from tools import constants as c  # pylint: disable=E0401

from ...utils import backup_crypto
from ...utils.project_backup import iter_project_backup_sql, iter_pg_dump

PROMPT_LIB_MODE = "prompt_lib"

FULL_MODE_PERMISSION = "projects.projects.backup.full"

PROJECT_DOWNLOAD_PERMISSION = "models.project_backup.download"

SAFE_MODES = ("safe", "sanitized", "default")
FULL_MODES = ("full", "raw", "as_is")

FALSE_VALUES = ("0", "false", "no", "off")


def _slugify(value):
    slug = re.sub(r"[^0-9a-zA-Z]+", "-", str(value or "")).strip("-").lower()
    return slug[:48] or "project"


def _safe_stream(connection, project_id, schema, project_name, exclude_tables):
    """ Generate the redacted SQL dump, releasing the connection at the end """
    def generate():
        try:
            for chunk in iter_project_backup_sql(
                    connection,
                    project_id=project_id,
                    schema=schema,
                    project_name=project_name,
                    safe_mode=True,
                    extra_excluded_tables=exclude_tables,
            ):
                yield chunk.encode("utf-8")
        except Exception as exc:  # pylint: disable=W0703
            log.exception("project_backup: safe export failed for %s", schema)
            yield "\nROLLBACK;\n-- export failed: {}\n".format(exc).encode("utf-8")
        finally:
            try:
                connection.rollback()
            except Exception:  # pylint: disable=W0703
                pass
            connection.close()
    #
    return generate()


def _full_stream(schema):
    """ Generate a raw pg_dump of the schema """
    return iter_pg_dump(
        schema=schema,
        host=c.POSTGRES_HOST,
        port=c.POSTGRES_PORT,
        user=c.POSTGRES_USER,
        password=c.POSTGRES_PASSWORD,
        database=c.POSTGRES_DB,
    )


def resolve_encryption(policy, plain_requested=False):
    """ Decide whether this download is encrypted: (encrypt, master_key, error) """
    if policy == backup_crypto.POLICY_DISABLED:
        return False, None, None
    #
    if plain_requested:
        if policy == backup_crypto.POLICY_REQUIRED:
            return False, None, "unencrypted backups are not allowed on this setup"
        return False, None, None
    #
    master_key = backup_crypto.configured_master_key()
    #
    if master_key is None:
        if policy == backup_crypto.POLICY_REQUIRED:
            return False, None, "SECRETS_MASTER_KEY is not configured, " \
                                "backups can not be encrypted"
        # A setup without a master key keeps working as before
        log.warning(
            "project_backup: SECRETS_MASTER_KEY is not set, exporting unencrypted",
        )
        return False, None, None
    #
    return True, master_key, None


def make_backup_response(project_id, safe_mode, exclude_tables, encrypt=False, master_key=None):
    """ Resolve the project schema and return a streaming SQL download """
    from tools import project_constants as pc  # pylint: disable=E0401,C0415
    schema = pc["PROJECT_SCHEMA_TEMPLATE"].format(project_id)
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
                connection.close()
                return {"ok": False, "error": "project schema not found"}, 404
            #
            cursor.execute(
                'select name from {}."project" where id = %s'.format(c.POSTGRES_SCHEMA),
                (project_id,),
            )
            row = cursor.fetchone()
            project_name = row[0] if row else None
    except Exception:  # pylint: disable=W0703
        connection.close()
        log.exception("project_backup: failed to resolve project %s", project_id)
        return {"ok": False, "error": "failed to resolve project"}, 500
    #
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
    filename = "elitea-backup-{}-{}-{}-{}.sql".format(
        project_id, _slugify(project_name), "safe" if safe_mode else "full", timestamp,
    )
    #
    mimetype = "application/sql"
    if encrypt:
        filename += backup_crypto.ENVELOPE_SUFFIX
        mimetype = backup_crypto.ENVELOPE_MIMETYPE
    #
    log.info(
        "project_backup: exporting project %s (%s) in %s mode (encrypted=%s)",
        project_id, schema, "safe" if safe_mode else "full", encrypt,
    )
    #
    if safe_mode:
        stream = _safe_stream(connection, project_id, schema, project_name, exclude_tables)
    else:
        connection.close()
        stream = _full_stream(schema)
    #
    if encrypt:
        stream = backup_crypto.iter_encrypt(stream, master_key)
    #
    return flask.Response(
        stream,
        mimetype=mimetype,
        headers={
            "Content-Disposition": 'attachment; filename="{}"'.format(filename),
            "X-Content-Type-Options": "nosniff",
        },
    )


def _requested_exclude_tables():
    return [
        item for item in (flask.request.args.get("exclude_tables") or "").split(",")
        if item.strip()
    ]


def _plain_requested():
    return (flask.request.args.get("encrypt") or "").strip().lower() in FALSE_VALUES


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=R0903
    """ API """

    @register_openapi(
        name="Download Project Backup",
        description="Download a SQL backup of a single project schema. "
                    "In the default 'safe' mode sensitive tables are skipped and "
                    "credential-bearing columns / JSON keys are redacted. "
                    "The 'full' mode returns a plain pg_dump of the schema as-is, "
                    "including DDL and any plaintext secrets, and requires the "
                    "'projects.projects.backup.full' permission. "
                    "The artifact is encrypted with a key derived from this setup's "
                    "SECRETS_MASTER_KEY and downloads as .sql.enc; it can only be "
                    "restored where that master key matches.",
        parameters=[
            {"name": "project_id", "in": "path", "schema": {"type": "integer"},
             "description": "Project ID to back up."},
            {"name": "mode", "in": "query",
             "schema": {"type": "string", "enum": ["safe", "full"], "default": "safe"},
             "description": "safe (default, redacted, data only) or full (raw pg_dump)."},
            {"name": "exclude_tables", "in": "query", "schema": {"type": "string"},
             "description": "Comma-separated extra tables to skip (safe mode only)."},
            {"name": "encrypt", "in": "query",
             "schema": {"type": "boolean", "default": True},
             "description": "Pass false to download a plain .sql artifact instead of an "
                            "encrypted .sql.enc one, e.g. to move a backup to a setup "
                            "with a different SECRETS_MASTER_KEY. Refused when the "
                            "platform requires encrypted backups."},
        ],
    )
    @auth.decorators.check_api({
        "permissions": ["projects.projects.backup.download"],
        "recommended_roles": {
            "administration": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
            "default": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
            "developer": {"super_admin": True, "admin": False, "viewer": False, "editor": False},
        }})
    def get(self, project_id: int, **kwargs):  # pylint: disable=R0911,R0914
        """ Process GET """
        _ = kwargs
        #
        requested_mode = (flask.request.args.get("mode") or "safe").strip().lower()
        #
        if requested_mode in SAFE_MODES:
            safe_mode = True
        elif requested_mode in FULL_MODES:
            safe_mode = False
        else:
            return {"ok": False, "error": "unknown mode"}, 400
        #
        if not safe_mode:
            current_permissions = auth.resolve_permissions(mode="administration")
            if not auth.has_access(current_permissions, [FULL_MODE_PERMISSION]):
                return {"ok": False, "error": "access_denied"}, 403
        #
        # Opting out of encryption stays here: this permission already grants a
        # raw pg_dump, so it exposes nothing new, and it is the way a backup
        # reaches a setup with a different SECRETS_MASTER_KEY.
        #
        encrypt, master_key, error = resolve_encryption(
            backup_crypto.handler_policy(self), _plain_requested(),
        )
        if error is not None:
            return {"ok": False, "error": error}, 400
        #
        return make_backup_response(
            project_id, safe_mode, _requested_exclude_tables(), encrypt, master_key,
        )


class PromptLibAPI(api_tools.APIModeHandler):  # pylint: disable=R0903
    """ API """

    @register_openapi(
        name="Download Project Backup (project scope)",
        description="Download a redacted SQL backup of the current project schema. "
                    "Only the 'safe' mode is available here: sensitive tables are "
                    "skipped and credential-bearing columns / JSON keys are redacted. "
                    "Raw pg_dump exports are available in the administration API only. "
                    "The artifact is encrypted with a key derived from this setup's "
                    "SECRETS_MASTER_KEY and downloads as .sql.enc; it can only be "
                    "restored where that master key matches.",
        parameters=[
            {"name": "project_id", "in": "path", "schema": {"type": "integer"},
             "description": "Project ID to back up."},
            {"name": "exclude_tables", "in": "query", "schema": {"type": "string"},
             "description": "Comma-separated extra tables to skip."},
        ],
    )
    @auth.decorators.check_api({
        "permissions": [PROJECT_DOWNLOAD_PERMISSION],
        "recommended_roles": {
            "administration": {"super_admin": True, "admin": True, "viewer": False, "editor": True},
            "default": {"super_admin": True, "admin": True, "viewer": False, "editor": True},
            "developer": {"super_admin": True, "admin": True, "viewer": False, "editor": True},
        }})
    def get(self, project_id: int, **kwargs):
        """ Process GET """
        _ = kwargs
        #
        # Project scope never exposes the raw pg_dump: it carries DDL and any
        # plaintext credentials the safe mode redacts.
        #
        requested_mode = (flask.request.args.get("mode") or "safe").strip().lower()
        if requested_mode not in SAFE_MODES:
            return {"ok": False, "error": "only safe mode is available for projects"}, 403
        #
        # Project scope follows the platform policy: no opting out of encryption
        #
        encrypt, master_key, error = resolve_encryption(backup_crypto.handler_policy(self))
        if error is not None:
            return {"ok": False, "error": error}, 400
        #
        return make_backup_response(
            project_id, True, _requested_exclude_tables(), encrypt, master_key,
        )


class API(api_tools.APIBase):  # pylint: disable=R0903
    """ API """

    url_params = [
        "<string:mode>/<int:project_id>",
    ]

    mode_handlers = {
        'administration': AdminAPI,
        PROMPT_LIB_MODE: PromptLibAPI,
    }
