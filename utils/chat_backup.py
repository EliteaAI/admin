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

""" Project backup: chats of the project and their attachment files

A backup with chats carries the chat tables below next to the regular safe
backup. With attachments it becomes an encrypted ZIP:

    info.json       - stored first and uncompressed, so the restore dialog can
                      recognize the archive from its first bytes
    backup.sql      - the safe SQL backup including the chat tables
    attachments/<bucket>/<name>
    manifest.json   - written last, lists every attachment and its status
"""

import json
import struct
import hashlib
import datetime
import zipfile


CHATS_NONE = "none"
CHATS_WITHOUT_ATTACHMENTS = "without_attachments"
CHATS_WITH_ATTACHMENTS = "with_attachments"
CHAT_OPTIONS = (CHATS_NONE, CHATS_WITHOUT_ATTACHMENTS, CHATS_WITH_ATTACHMENTS)

FORMAT_VERSION = "1"

#
# Chat tables a backup with chats carries. Share tokens, per-user selection,
# traces, summaries and context payloads stay excluded (SAFE_MODE_EXCLUDED_TABLES)
#
CHAT_BACKUP_TABLES = frozenset((
    "chat_conversations",
    "chat_conversation_folders",
    "chat_message_group",
    "chat_message_items",
    "chat_messages_text",
    "chat_messages_attachment",
    "chat_messages_canvas",
    "chat_canvas_versions",
    "chat_canvas_version_authors",
    "chat_participants",
    "chat_participant_mapping",
))

# Context items live in chat_messages_context, which is not backed up
CONTEXT_ITEM_TYPE = "context_message"

ZIP_INFO_NAME = "info.json"
ZIP_SQL_NAME = "backup.sql"
ZIP_MANIFEST_NAME = "manifest.json"
ZIP_ATTACHMENTS_DIR = "attachments/"
ZIP_MAGIC = b"PK\x03\x04"

ATTACHMENT_OK = "ok"
ATTACHMENT_MISSING = "missing"


def _quote(identifier):
    return '"{}"'.format(str(identifier).replace('"', '""'))


def conversation_scope_sql(schema, user_id):
    """ Conversations a backup carries: team (non-private) chats plus the
        private chats of the user taking the backup """
    return "select id from {}.chat_conversations where not is_private or author_id = {}".format(
        _quote(schema), int(user_id),
    )


def chat_row_filters(schema, user_id):
    """ table -> WHERE clause limiting it to the rows of the backed up conversations """
    s = _quote(schema)
    scope = conversation_scope_sql(schema, user_id)
    groups = "select id from {}.chat_message_group where conversation_id in ({})".format(s, scope)
    items = (
        "select id from {}.chat_message_items where item_type <> '{}'"
        " and message_group_id in ({})"
    ).format(s, CONTEXT_ITEM_TYPE, groups)
    versions = "select id from {}.chat_canvas_versions where canvas_item_id in ({})".format(s, items)
    participants = " union ".join((
        "select participant_id from {}.chat_participant_mapping where conversation_id in ({})".format(s, scope),
        "select author_participant_id from {}.chat_message_group where conversation_id in ({})".format(s, scope),
        "select sent_to_id from {}.chat_message_group where conversation_id in ({})".format(s, scope),
        "select attachment_participant_id from {}.chat_conversations where id in ({})".format(s, scope),
        "select participant_id from {}.chat_canvas_version_authors where canvas_version_id in ({})".format(
            s, versions),
    ))
    #
    return {
        "chat_conversations": "id in ({})".format(scope),
        "chat_conversation_folders": "id in (select folder_id from {}.chat_conversations"
                                     " where id in ({})) or owner_id = {}".format(s, scope, int(user_id)),
        "chat_participant_mapping": "conversation_id in ({})".format(scope),
        "chat_message_group": "conversation_id in ({})".format(scope),
        "chat_message_items": "id in ({})".format(items),
        "chat_messages_text": "id in ({})".format(items),
        "chat_messages_attachment": "id in ({})".format(items),
        "chat_messages_canvas": "id in ({})".format(items),
        "chat_canvas_versions": "id in ({})".format(versions),
        "chat_canvas_version_authors": "canvas_version_id in ({})".format(versions),
        "chat_participants": "id in ({})".format(participants),
    }


def resolve_chat_scope(cursor, schema, user_id):
    """ Counts and attachment references of the conversations a backup carries """
    scope = conversation_scope_sql(schema, user_id)
    s = _quote(schema)
    #
    cursor.execute("select count(*) from ({}) c".format(scope))
    chats_count = cursor.fetchone()[0]
    #
    cursor.execute(
        "select distinct a.bucket, a.name from {s}.chat_messages_attachment a"
        " join {s}.chat_message_items i on i.id = a.id"
        " join {s}.chat_message_group g on g.id = i.message_group_id"
        " where g.conversation_id in ({scope})"
        " order by a.bucket, a.name".format(s=s, scope=scope)
    )
    attachments = [{"bucket": row[0], "name": row[1]} for row in cursor.fetchall()]
    #
    return {"chats_count": chats_count, "attachments": attachments}


def attach_file_sizes(attachments, list_bucket):
    """ Fill the size of each attachment from a bucket listing; a file the
        listing does not have is marked missing """
    listings = {}
    for item in attachments:
        bucket = item["bucket"]
        if bucket not in listings:
            try:
                listings[bucket] = {entry["name"]: entry["size"] for entry in list_bucket(bucket)}
            except Exception:  # pylint: disable=W0703
                listings[bucket] = {}
        #
        size = listings[bucket].get(item["name"])
        item["size"] = size or 0
        item["status"] = ATTACHMENT_OK if size is not None else ATTACHMENT_MISSING
    #
    return attachments


def summarize(scope):
    """ Numbers shown before a backup is taken """
    attachments = scope["attachments"]
    return {
        "chats_count": scope["chats_count"],
        "attachments_count": len(attachments),
        "attachments_size": sum(item.get("size") or 0 for item in attachments),
        "missing_attachments": sum(1 for item in attachments if item.get("status") == ATTACHMENT_MISSING),
    }


def attachment_path(bucket, name):
    return "{}{}/{}".format(ZIP_ATTACHMENTS_DIR, bucket, name)


class _Sink:
    """ Write-only buffer ZipFile streams into; drained after every write """

    def __init__(self):
        self.buffer = bytearray()

    def write(self, data):
        self.buffer += data
        return len(data)

    def flush(self):
        """ Nothing to flush: the generator drains the buffer """

    def drain(self):
        data = bytes(self.buffer)
        self.buffer.clear()
        return data


def iter_backup_zip(info, sql_chunks, attachments, read_file):  # pylint: disable=R0914
    """ Stream the backup archive: info, SQL, attachment files, manifest

    sql_chunks yields bytes; read_file(bucket, name) returns the file content.
    Attachments are stored uncompressed (they are mostly compressed already),
    which also keeps the archive free of compression ratios to defend against.
    """
    sink = _Sink()
    archive = zipfile.ZipFile(sink, "w", allowZip64=True)  # pylint: disable=R1732
    now = datetime.datetime.now().timetuple()[:6]
    #
    def entry(name, compress_type):
        item = zipfile.ZipInfo(name, date_time=now)
        item.compress_type = compress_type
        return item
    #
    archive.writestr(entry(ZIP_INFO_NAME, zipfile.ZIP_STORED), json.dumps(info))
    yield sink.drain()
    #
    with archive.open(entry(ZIP_SQL_NAME, zipfile.ZIP_DEFLATED), "w", force_zip64=True) as target:
        for chunk in sql_chunks:
            target.write(chunk)
            data = sink.drain()
            if data:
                yield data
    yield sink.drain()
    #
    files = []
    for item in attachments:
        record = {"bucket": item["bucket"], "name": item["name"], "size": item.get("size") or 0}
        content = None
        if item.get("status") != ATTACHMENT_MISSING:
            try:
                content = read_file(item["bucket"], item["name"])
            except Exception:  # pylint: disable=W0703
                content = None
        #
        if content is None:
            record["status"] = ATTACHMENT_MISSING
        else:
            record.update({
                "status": ATTACHMENT_OK,
                "size": len(content),
                "checksum": hashlib.sha256(content).hexdigest(),
                "path": attachment_path(item["bucket"], item["name"]),
            })
            archive.writestr(entry(record["path"], zipfile.ZIP_STORED), content)
            yield sink.drain()
        files.append(record)
    #
    manifest = dict(info, attachments=files)
    manifest["missing_attachments"] = sum(1 for item in files if item["status"] == ATTACHMENT_MISSING)
    archive.writestr(entry(ZIP_MANIFEST_NAME, zipfile.ZIP_DEFLATED), json.dumps(manifest))
    archive.close()
    yield sink.drain()


def make_info(project_id, project_name, created_by, mode, scope):
    """ Summary written in front of the archive and repeated in the manifest """
    return {
        "format_version": FORMAT_VERSION,
        "project_id": project_id,
        "project_name": project_name,
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "created_by": created_by,
        "chats_included": mode,
        "chats_count": scope["chats_count"],
        "attachments_count": len(scope["attachments"]),
        "attachments_size": sum(item.get("size") or 0 for item in scope["attachments"]),
    }


def is_zip(head):
    return head[:len(ZIP_MAGIC)] == ZIP_MAGIC


def read_zip_info(head):
    """ The info.json of an archive, read from its first local file entry """
    if len(head) < 30 or not is_zip(head):
        return None
    #
    name_length, extra_length = struct.unpack("<HH", head[26:30])
    name = head[30:30 + name_length].decode("utf-8", "replace")
    if name != ZIP_INFO_NAME:
        return None
    #
    start = 30 + name_length + extra_length
    try:
        info, _ = json.JSONDecoder().raw_decode(head[start:].decode("utf-8", "replace"))
    except ValueError:
        return None
    return info if isinstance(info, dict) else None
