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
import urllib.parse

import flask  # pylint: disable=E0401

from pylon.core.tools import log  # pylint: disable=E0611,E0401

from tools import auth, api_tools, register_openapi  # pylint: disable=E0401
from tools import context  # pylint: disable=E0401
from tools import constants as c  # pylint: disable=E0401

from ...utils import backup_crypto
from ...utils import chat_backup
from ...utils.chat_restore import AttachmentRestorer, iter_zip_sql, open_backup_zip
from ...utils.project_restore import (
    KIND_SAFE, KIND_PG_DUMP, HEADER_SCAN_BYTES, SAFE_RESTORE_DENIED_TABLES,
    detect_artifact_kind, parse_header, pg_dump_schema, restore_safe_backup,
    run_psql, server_settings,
)


PROMPT_LIB_MODE = "prompt_lib"

FULL_MODE_PERMISSION = "projects.projects.restore.full"

PROJECT_BACKUP_PERMISSION = "models.project_backup"

PROJECT_RESTORE_PERMISSION = "models.project_backup.restore"

READ_CHUNK = 262144
TRUE_VALUES = ("1", "true", "yes", "on")

SAFE_MODES = ("safe", "sanitized", "default")
FULL_MODES = ("full", "raw", "as_is")

DEFAULT_MAX_ARCHIVE_MB = 4096


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


def _is_same_site_request():
    """ Reject a browser request initiated from another site (CSRF)

    Sec-Fetch-Site and Origin are set by the browser itself and can not be
    forged by page script. A non-browser client (curl, CI) sends neither and
    stays gated by permissions only, as before.
    """
    fetch_site = flask.request.headers.get("Sec-Fetch-Site")
    if fetch_site is not None:
        return fetch_site.strip().lower() in ("same-origin", "same-site")
    #
    origin = flask.request.headers.get("Origin")
    if not origin:
        return True
    #
    try:
        source = urllib.parse.urlsplit(origin).hostname
    except ValueError:
        return False
    #
    return bool(source) and source == flask.request.host.split(":")[0]


def _is_own_personal_project(project_id):
    """ A private project is created with its owner as editor / viewer / monitor,
    never as its admin, so restoring into it is authorized by ownership instead """
    current_user = auth.current_user()
    user_id = current_user.get("id") if current_user else None
    #
    if not user_id:
        return False
    #
    try:
        personal_project_id = context.rpc_manager.timeout(5). \
            projects_get_personal_project_id(user_id)
    except Exception:  # pylint: disable=W0703
        log.exception("project_restore: failed to resolve the personal project of user %s", user_id)
        return False
    #
    return personal_project_id == project_id


def _project_member_ids(project_id):
    """ Users of the project, or None when they can not be resolved """
    try:
        return context.rpc_manager.timeout(5).admin_get_users_ids_in_project(project_id=project_id)
    except Exception:  # pylint: disable=W0703
        log.exception("project_restore: failed to resolve the users of project %s", project_id)
        return None


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


def _text_chunks(open_bytes):
    """ Re-readable text stream, decoded across chunk boundaries """
    def opener():
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        for chunk in open_bytes():
            text = decoder.decode(chunk)
            if text:
                yield text
        tail = decoder.decode(b"", True)
        if tail:
            yield tail
    #
    return opener


def _spool_decrypted(open_bytes):
    """ Decrypted copy of the artifact in a temp file: a ZIP needs random access """
    target = tempfile.TemporaryFile()  # pylint: disable=R1732
    for chunk in open_bytes():
        target.write(chunk)
    target.seek(0)
    return target


def _max_archive_bytes(handler):
    module = getattr(handler, "module", None)
    config = getattr(getattr(module, "descriptor", None), "config", None) or {}
    try:
        megabytes = int(config.get("backup_max_archive_mb", DEFAULT_MAX_ARCHIVE_MB))
    except (TypeError, ValueError):
        megabytes = DEFAULT_MAX_ARCHIVE_MB
    return megabytes * 1024 * 1024


def _requested_restore_chats():
    value = _param("restore_chats").strip().lower() or chat_backup.CHATS_NONE
    return value if value in chat_backup.CHAT_OPTIONS else None


def _attachment_settings(project_id):
    """ (bucket, retention days) chat attachments of the project are stored with """
    try:
        from tools import VaultClient  # pylint: disable=E0401,C0415
        secrets = VaultClient(project_id).get_all_secrets()
        return (
            secrets.get("default_attachment_bucket") or "attachments",
            int(secrets.get("chat_bucket_retention_days", 365)),
        )
    except Exception:  # pylint: disable=W0703
        return "attachments", 365


def _attachment_restorer(project_id, archive, manifest, restore_chats):
    from tools import MinioClient  # pylint: disable=E0401,C0415
    bucket, retention_days = _attachment_settings(project_id)
    return AttachmentRestorer(
        MinioClient.from_project_id(project_id), bucket,
        archive=archive, manifest=manifest,
        with_files=restore_chats == chat_backup.CHATS_WITH_ATTACHMENTS,
        retention_days=retention_days,
    )


def _verify_stream(open_bytes):
    """ Walk the whole artifact so a failure raises before anything is applied """
    for _ in open_bytes():
        pass


def _read_head(open_bytes, limit):
    """ First bytes of the artifact, without consuming the opener """
    head = bytearray()
    #
    for chunk in open_bytes():
        head += chunk
        if len(head) >= limit:
            break
    #
    return bytes(head[:limit])


def apply_uploaded_backup(  # pylint: disable=R0911,R0912,R0913,R0914,R0915
        project_id, allow_pg_dump=True, allow_mismatch_override=True, restrict_tables=False,
        policy=backup_crypto.POLICY_ENABLED, max_archive_bytes=DEFAULT_MAX_ARCHIVE_MB * 1024 * 1024,
):
    """ Apply the uploaded artifact to the project schema """
    if not _is_same_site_request():
        return {"ok": False, "error": "access_denied"}, 403
    #
    requested_mode = _param("mode").strip().lower() or "safe"
    #
    if requested_mode in SAFE_MODES:
        full_mode = False
    elif requested_mode in FULL_MODES:
        full_mode = True
    else:
        return {"ok": False, "error": "unknown mode"}, 400
    #
    if full_mode:
        if not allow_pg_dump:
            return {
                "ok": False,
                "error": "raw pg_dump artifacts can only be restored by platform admins",
            }, 403
        current_permissions = auth.resolve_permissions(mode="administration")
        if not auth.has_access(current_permissions, [FULL_MODE_PERMISSION]):
            return {"ok": False, "error": "access_denied"}, 403
    #
    if "file" not in flask.request.files:
        return {"ok": False, "error": "no file provided"}, 400
    #
    tables = [item.strip() for item in _param("tables").split(",") if item.strip()]
    include_parents = _flag("include_parents")
    truncate = _flag("truncate")
    dry_run = _flag("dry_run")
    inspect_only = _flag("inspect")
    allow_mismatch = _flag("allow_project_mismatch") if allow_mismatch_override else False
    restore_chats = _requested_restore_chats()
    if restore_chats is None:
        return {"ok": False, "error": "unknown restore_chats option"}, 400
    #
    from tools import project_constants as pc  # pylint: disable=E0401,C0415
    schema = pc["PROJECT_SCHEMA_TEMPLATE"].format(project_id)
    #
    spool = tempfile.TemporaryFile()  # pylint: disable=R1732
    archive_spool = None
    archive = None
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
        # The envelope is checked on raw bytes, before anything is decoded:
        # a successful decrypt is what proves the artifact came from a setup
        # holding this SECRETS_MASTER_KEY, so nothing downstream ever sees a
        # hand-written file.
        #
        spool.seek(0)
        encrypted = backup_crypto.is_encrypted(spool.read(len(backup_crypto.ENVELOPE_MAGIC)))
        #
        open_bytes = _byte_chunks(spool)
        #
        if encrypted:
            master_key = backup_crypto.configured_master_key()
            if master_key is None:
                return {
                    "ok": False,
                    "error": "this backup is encrypted but SECRETS_MASTER_KEY is not "
                             "configured on this setup",
                }, 400
            open_bytes = backup_crypto.wrap_decrypt(open_bytes, master_key)
        elif policy == backup_crypto.POLICY_REQUIRED:
            return {
                "ok": False,
                "error": "only encrypted backups can be restored on this setup; "
                         "export the project again and upload the .sql.enc file",
            }, 400
        #
        raw_head = _read_head(open_bytes, HEADER_SCAN_BYTES)
        manifest = None
        #
        # A backup with chat attachments is a ZIP: the SQL part inside it is
        # what gets applied, the files are uploaded next to it
        if chat_backup.is_zip(raw_head):
            if chat_backup.read_zip_info(raw_head) is None:
                return {"ok": False, "error": "unrecognized backup file"}, 400
            archive_spool = _spool_decrypted(open_bytes) if encrypted else spool
            archive_spool.seek(0)
            archive, _, manifest = open_backup_zip(archive_spool, max_archive_bytes)
            open_bytes = iter_zip_sql(archive)
            raw_head = _read_head(open_bytes, HEADER_SCAN_BYTES)
        #
        head = raw_head.decode("utf-8", "replace")
        #
        kind = detect_artifact_kind(head)
        if kind is None:
            return {"ok": False, "error": "unrecognized backup file"}, 400
        #
        artifact = parse_header(head)
        artifact["has_attachment_files"] = archive is not None
        artifact["attachments_size"] = sum(
            item.get("size") or 0 for item in (manifest or {}).get("attachments") or []
            if item.get("status") == chat_backup.ATTACHMENT_OK
        )
        artifact["kind"] = kind
        artifact["filename"] = filename
        artifact["size"] = size
        artifact["encrypted"] = encrypted
        #
        # The dialog reads what a file carries as soon as it is picked
        if inspect_only:
            return {"ok": True, "inspect": True, "artifact": artifact}, 200
        #
        source_project = artifact.get("project_id")
        if isinstance(source_project, int) and source_project != project_id \
                and not allow_mismatch:
            if allow_mismatch_override:
                error = "artifact belongs to project {}; pass " \
                        "allow_project_mismatch=true to restore it into project {}".format(
                            source_project, project_id)
            else:
                error = "artifact belongs to project {} and can not be restored " \
                        "into project {}".format(source_project, project_id)
            return {"ok": False, "error": error, "artifact": artifact}, 409
        #
        # Entities coming from another project would stay attributed to its
        # users, so ownership moves to whoever performs the restore. The owner
        # columns that hold a project rather than a user move to this project.
        #
        owner_user_id = None
        owner_project_id = None
        source_project_id = None
        if isinstance(source_project, int) and source_project != project_id:
            current_user = auth.current_user()
            owner_user_id = current_user.get("id") if current_user else None
            owner_project_id = project_id
            source_project_id = source_project
        #
        # The requested mode decides how the artifact is applied, so the detected
        # kind has to agree with it: an unexpected file is reported instead of
        # silently taking the other path.
        if full_mode and kind != KIND_PG_DUMP:
            return {
                "ok": False,
                "error": "this file is a redacted project backup, not a raw pg_dump;"
                         " restore it in safe mode",
                "artifact": artifact,
            }, 400
        #
        if not full_mode and kind != KIND_SAFE:
            return {
                "ok": False,
                "error": "this file is a raw pg_dump and can not be restored in safe mode",
                "artifact": artifact,
            }, 400
        #
        if full_mode and tables:
            return {
                "ok": False,
                "error": "partial restore is not supported for pg_dump artifacts",
            }, 400
        #
        # A plain pg_dump rebuilds the schema it was taken from: it carries its
        # own CREATE SCHEMA, fully qualified names and a search_path reset, so
        # the target search_path is ignored and the restore would recreate the
        # source project instead of filling this one.
        #
        if full_mode:
            dump_schema = pg_dump_schema(head)
            artifact["dump_schema"] = dump_schema
            #
            if dump_schema is not None and dump_schema != schema:
                return {
                    "ok": False,
                    "error": "this pg_dump rebuilds schema {} and can not be retargeted "
                             "at {}; restore it in safe mode instead".format(
                                 dump_schema, schema),
                    "artifact": artifact,
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
                #
                # Client tools newer than the server write parameters it does
                # not know into the dump preamble; those SETs are dropped
                known_settings = server_settings(cursor) if full_mode else None
            connection.rollback()
            #
            log.info(
                "project_restore: applying %s artifact to %s (%s, dry_run=%s)",
                kind, schema, "partial" if tables else "full", dry_run,
            )
            #
            # Without the files in the backup, attachments can only be re-linked
            if restore_chats == chat_backup.CHATS_WITH_ATTACHMENTS and archive is None:
                restore_chats = chat_backup.CHATS_WITHOUT_ATTACHMENTS
            #
            if kind == KIND_SAFE:
                handler = None
                if artifact["chats_included"] != chat_backup.CHATS_NONE \
                        and restore_chats != chat_backup.CHATS_NONE:
                    handler = _attachment_restorer(project_id, archive, manifest, restore_chats)
                current_user = auth.current_user()
                result = restore_safe_backup(
                    connection,
                    open_chunks=_text_chunks(open_bytes),
                    schema=schema,
                    tables=tables,
                    include_parents=include_parents,
                    truncate=truncate,
                    dry_run=dry_run,
                    denied_tables=SAFE_RESTORE_DENIED_TABLES if restrict_tables else (),
                    owner_user_id=owner_user_id,
                    owner_project_id=owner_project_id,
                    source_project_id=source_project_id,
                    member_user_ids=_project_member_ids(project_id),
                    backup_chats=artifact["chats_included"],
                    restore_chats=restore_chats,
                    chat_context={
                        "restorer_id": current_user.get("id") if current_user else None,
                        "source_project_id": artifact.get("project_id")
                        if isinstance(artifact.get("project_id"), int) else None,
                        "target_project_id": project_id,
                    },
                    attachment_handler=handler,
                )
                log.info(
                    "project_restore_applied: project %s (dry_run=%s, chats_included=%s,"
                    " restore_chats=%s, chats=%s, attachments=%s)",
                    project_id, dry_run, artifact["chats_included"], restore_chats,
                    result.get("chats"), {
                        k: v for k, v in (result.get("attachments") or {}).items()
                        if k != "failed_names"
                    },
                )
            else:
                # psql runs --single-transaction and commits on EOF, so a frame
                # that fails halfway through could still be committed before the
                # process is killed. The artifact is verified end to end first.
                if encrypted:
                    _verify_stream(open_bytes)
                #
                result = run_psql(
                    open_chunks=open_bytes,
                    schema=schema,
                    host=c.POSTGRES_HOST,
                    port=c.POSTGRES_PORT,
                    user=c.POSTGRES_USER,
                    password=c.POSTGRES_PASSWORD,
                    database=c.POSTGRES_DB,
                    dry_run=dry_run,
                    known_settings=known_settings,
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
        if archive is not None:
            archive.close()
        if archive_spool is not None and archive_spool is not spool:
            archive_spool.close()
        spool.close()
    #
    result["mode"] = "partial" if tables else "full"
    return {"ok": True, "artifact": artifact, "result": result}, 200


class AdminAPI(api_tools.APIModeHandler):  # pylint: disable=R0903
    """ API """

    @register_openapi(
        name="Restore Project Backup",
        description="Restore a backup produced by the project backup endpoint into a "
                    "project schema. Upload the .sql.enc (or .sql) file as multipart "
                    "form field 'file'. An encrypted artifact is decrypted and verified "
                    "with a key derived from this setup's SECRETS_MASTER_KEY, so only "
                    "artifacts produced by a setup sharing that key can be restored. "
                    "Without 'tables' the whole artifact is applied (full restore); with "
                    "'tables' only the listed tables are applied (partial restore). "
                    "In the default 'safe' mode the artifact is applied statement by "
                    "statement in one transaction, and only redacted project backups "
                    "are accepted. The 'full' mode pipes a raw pg_dump artifact to psql "
                    "and requires the 'projects.projects.restore.full' permission. "
                    "The uploaded file has to match the requested mode.",
        parameters=[
            {"name": "project_id", "in": "path", "schema": {"type": "integer"},
             "description": "Target project ID."},
            {"name": "mode", "in": "query",
             "schema": {"type": "string", "enum": ["safe", "full"], "default": "safe"},
             "description": "safe (default, redacted backup) or full (raw pg_dump)."},
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
        }})
    def post(self, project_id: int, **kwargs):
        """ Process POST """
        _ = kwargs
        #
        return apply_uploaded_backup(
            project_id, policy=backup_crypto.handler_policy(self),
            max_archive_bytes=_max_archive_bytes(self),
        )


class PromptLibAPI(api_tools.APIModeHandler):  # pylint: disable=R0903
    """ API """

    @register_openapi(
        name="Restore Project Backup (project scope)",
        description="Restore a redacted (safe) backup into this project. Upload the "
                    ".sql.enc (or .sql) file as multipart form field 'file'. An encrypted "
                    "artifact is decrypted and verified with a key derived from this "
                    "setup's SECRETS_MASTER_KEY, so only artifacts produced by a setup "
                    "sharing that key can be restored. Only the 'safe' mode is "
                    "available here, so only redacted project backups are accepted; raw "
                    "pg_dump restores stay in the administration API. "
                    "An artifact taken from another project is rejected unless "
                    "'allow_project_mismatch=true' is passed. Without 'tables' the whole "
                    "artifact is applied; with 'tables' only the listed tables.",
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
            {"name": "inspect", "in": "query", "schema": {"type": "boolean"},
             "description": "Only read the artifact header and return what it carries."},
            {"name": "restore_chats", "in": "query",
             "schema": {"type": "string", "enum": list(chat_backup.CHAT_OPTIONS), "default": "none"},
             "description": "Restore the chats of a backup that carries them: "
                            "without_attachments keeps attachment messages whose file the "
                            "project still has, with_attachments uploads the files of a ZIP "
                            "backup. Chats with a uuid the project already has are skipped."},
        ],
    )
    @auth.decorators.check_api({
        "permissions": [PROJECT_BACKUP_PERMISSION],
        "recommended_roles": {
            "administration": {"super_admin": True, "admin": True, "viewer": False, "editor": True},
            "default": {"super_admin": True, "admin": True, "viewer": False, "editor": True},
        }})
    def post(self, project_id: int, **kwargs):
        """ Process POST """
        _ = kwargs
        #
        # Safe artifacts may be restored across projects via allow_project_mismatch=true;
        # authorization is enforced on the TARGET project (models.project_backup.restore
        # on project_id in the URL), so the caller must hold that permission there --
        # or own the target, which is how a private project reaches its own restore.
        #
        current_permissions = auth.resolve_permissions(
            mode=PROMPT_LIB_MODE, project_id=project_id,
        )
        if not auth.has_access(current_permissions, [PROJECT_RESTORE_PERMISSION]) \
                and not _is_own_personal_project(project_id):
            return {"ok": False, "error": "access_denied",
                    "required": [PROJECT_RESTORE_PERMISSION]}, 403
        #
        # Tables a safe backup never exports are refused here instead of being
        # skipped: a hand-written artifact could otherwise insert role /
        # role_permission / user_role rows and grant itself permissions.
        #
        return apply_uploaded_backup(
            project_id, allow_pg_dump=False, allow_mismatch_override=True,
            restrict_tables=True, policy=backup_crypto.handler_policy(self),
            max_archive_bytes=_max_archive_bytes(self),
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
