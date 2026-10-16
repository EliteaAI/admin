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

""" Project restore: merge the chats of a backup into the target project

Chat rows are staged like the merged tables, then copied in with fresh ids:
ids of another project (or of chats deleted since the backup) would collide
with rows the target already has, and ON CONFLICT DO NOTHING would then hang
messages under someone else's conversation. A conversation whose uuid the
target already has is skipped together with everything under it.
"""

import json

from .chat_backup import CHAT_BACKUP_TABLES


# entity_name -> table holding the entity a participant points at
PARTICIPANT_ENTITY_TABLES = {
    "application": "applications",
    "toolkit": "elitea_tools",
    "skill": "skills",
    "prompt": "prompts",
}

USER_ENTITY = "user"
DUMMY_ENTITY = "dummy"

PLACEHOLDER_TEXT = "\U0001F4CE {} (file not available)"


def _quote(identifier):
    return '"{}"'.format(str(identifier).replace('"', '""'))


def _staging_name(table, suffix=""):
    return "pg_temp.{}".format(_quote("restore_{}{}".format(table, suffix)))


def _new_id(table):
    return "nextval(pg_get_serial_sequence('{}', 'id'))".format(_quote(table))


def _create_map(cursor, table):
    name = _staging_name(table, "_map")
    cursor.execute(
        "CREATE TEMP TABLE {} (old_id bigint PRIMARY KEY, new_id bigint NOT NULL)"
        " ON COMMIT DROP".format(name)
    )
    return name


def ensure_staged(cursor, staged, existing):
    """ An empty staging table for every chat table the backup had no rows for """
    for table in sorted(CHAT_BACKUP_TABLES.intersection(existing)):
        if table not in staged:
            staged[table] = _staging_name(table)
            cursor.execute(
                "CREATE TEMP TABLE {} (LIKE {} INCLUDING DEFAULTS) ON COMMIT DROP".format(
                    staged[table], _quote(table),
                )
            )


def _copy(cursor, table, columns, source, mapping=None, overrides=None, where="", joins=""):  # pylint: disable=R0913
    """ INSERT INTO table SELECT ... FROM staging; id from mapping when given """
    overrides = overrides or {}
    names = [name for name in columns if not (mapping and name == "id")]
    expressions = [overrides.get(name, "s.{}".format(_quote(name))) for name in names]
    if mapping:
        names.insert(0, "id")
        expressions.insert(0, "m.new_id")
        joins = " JOIN {} m ON m.old_id = s.id{}".format(mapping, joins)
    #
    cursor.execute(
        "INSERT INTO {} ({}) SELECT {} FROM {} s{}{} ON CONFLICT DO NOTHING".format(
            _quote(table), ", ".join(_quote(name) for name in names),
            ", ".join(expressions), source, joins, " WHERE {}".format(where) if where else "",
        )
    )
    return max(cursor.rowcount, 0)


def _table_has_row(cursor, table, row_id, existing):
    if table not in existing:
        return True
    cursor.execute("SELECT 1 FROM {} WHERE id = %s".format(_quote(table)), (row_id,))
    return cursor.fetchone() is not None


def _target_participant(cursor, cache, entity_name, entity_meta, meta, uuid):  # pylint: disable=R0913
    """ Id of the target participant for (entity_name, entity_meta), created when missing """
    key = (entity_name, json.dumps(entity_meta, sort_keys=True))
    if key in cache:
        return cache[key]
    #
    cursor.execute(
        "SELECT id FROM chat_participants WHERE entity_name = %s AND entity_meta = %s::jsonb"
        " ORDER BY id LIMIT 1",
        (entity_name, json.dumps(entity_meta)),
    )
    row = cursor.fetchone()
    if row is None:
        cursor.execute(
            "INSERT INTO chat_participants (uuid, entity_name, entity_meta, meta)"
            " SELECT CASE WHEN %s::uuid IS NULL"
            " OR EXISTS (SELECT 1 FROM chat_participants WHERE uuid = %s::uuid)"
            " THEN gen_random_uuid() ELSE %s::uuid END, %s, %s::jsonb, %s::json RETURNING id",
            (uuid, uuid, uuid, entity_name, json.dumps(entity_meta), json.dumps(meta or {})),
        )
        row = cursor.fetchone()
    #
    cache[key] = row[0]
    return row[0]


def _map_participants(cursor, staged, existing, context):  # pylint: disable=R0914
    """ Map every backup participant onto a target one, return the users that
        were re-mapped to the restoring user: old participant id -> original name """
    mapping = _create_map(cursor, "chat_participants")
    members = context.get("member_user_ids")
    members = {int(item) for item in members} if members is not None else None
    restorer_id = context.get("restorer_id")
    source_project_id = context.get("source_project_id")
    target_project_id = context.get("target_project_id")
    #
    cursor.execute(
        "SELECT id, uuid::text, entity_name, entity_meta::text, meta::text FROM {}".format(
            staged["chat_participants"],
        )
    )
    rows = cursor.fetchall()
    #
    cache = {}
    foreign = {}
    dummy = None
    #
    for old_id, uuid, entity_name, entity_meta, meta in rows:
        entity_meta = json.loads(entity_meta or "{}")
        meta = json.loads(meta or "{}")
        #
        if source_project_id is not None and entity_meta.get("project_id") == source_project_id:
            entity_meta = dict(entity_meta, project_id=target_project_id)
        #
        if entity_name == USER_ENTITY:
            user_id = entity_meta.get("id")
            if members is not None and restorer_id is not None and user_id not in members:
                foreign[old_id] = meta.get("user_name") or "User {}".format(user_id)
                entity_meta = dict(entity_meta, id=restorer_id)
                meta = {}
        #
        table = PARTICIPANT_ENTITY_TABLES.get(entity_name)
        if table and entity_meta.get("project_id") == target_project_id \
                and not _table_has_row(cursor, table, entity_meta.get("id"), existing):
            # The agent / toolkit is not in this project: its messages go to the default assistant
            if dummy is None:
                dummy = _target_participant(cursor, cache, DUMMY_ENTITY, {}, {}, None)
            new_id = dummy
        else:
            new_id = _target_participant(cursor, cache, entity_name, entity_meta, meta, uuid)
        #
        cursor.execute("INSERT INTO {} VALUES (%s, %s)".format(mapping), (old_id, new_id))
    #
    foreign_table = _staging_name("chat_participants", "_foreign")
    cursor.execute(
        "CREATE TEMP TABLE {} (old_id bigint PRIMARY KEY, name text) ON COMMIT DROP".format(foreign_table)
    )
    for old_id, name in foreign.items():
        cursor.execute("INSERT INTO {} VALUES (%s, %s)".format(foreign_table), (old_id, name))
    #
    return mapping, foreign_table


def _foreign_user_filter(column, context):
    """ SQL expression giving the restoring user for users who are not members """
    members = context.get("member_user_ids")
    restorer_id = context.get("restorer_id")
    if members is None or restorer_id is None:
        return None
    member_list = ", ".join(str(int(item)) for item in members) or "NULL"
    return "CASE WHEN s.{0} IN ({1}) THEN s.{0} ELSE {2} END".format(
        _quote(column), member_list, int(restorer_id),
    )


def merge_chats(cursor, staged, columns_by_table, existing, context):  # pylint: disable=R0914,R0915
    """ Copy the staged chats into the target, return (summary, restored attachments) """
    ensure_staged(cursor, staged, existing)
    columns = {table: sorted(columns_by_table[table]) for table in staged if table in columns_by_table}
    #
    participants, foreign = _map_participants(cursor, staged, existing, context)
    #
    # Folders: matched on uuid, otherwise copied with a new id
    folders = _create_map(cursor, "chat_conversation_folders")
    cursor.execute(
        "INSERT INTO {m} SELECT s.id, t.id FROM {s} s JOIN chat_conversation_folders t"
        " ON t.uuid = s.uuid".format(m=folders, s=staged["chat_conversation_folders"])
    )
    cursor.execute(
        "INSERT INTO {m} SELECT s.id, {new} FROM {s} s WHERE NOT EXISTS"
        " (SELECT 1 FROM {m} x WHERE x.old_id = s.id)".format(
            m=folders, s=staged["chat_conversation_folders"], new=_new_id("chat_conversation_folders"))
    )
    owner = _foreign_user_filter("owner_id", context)
    _copy(
        cursor, "chat_conversation_folders", columns["chat_conversation_folders"],
        staged["chat_conversation_folders"], folders,
        overrides={"owner_id": owner} if owner else None,
        where="NOT EXISTS (SELECT 1 FROM chat_conversation_folders t WHERE t.uuid = s.uuid)",
    )
    #
    # Conversations: one the target already has (same uuid) is skipped with all it holds
    conversations = _create_map(cursor, "chat_conversations")
    cursor.execute(
        "INSERT INTO {m} SELECT s.id, {new} FROM {s} s WHERE NOT EXISTS"
        " (SELECT 1 FROM chat_conversations t WHERE t.uuid = s.uuid)".format(
            m=conversations, s=staged["chat_conversations"], new=_new_id("chat_conversations"))
    )
    overrides = {
        "folder_id": "(SELECT f.new_id FROM {} f WHERE f.old_id = s.folder_id)".format(folders),
        "attachment_participant_id": "(SELECT p.new_id FROM {} p WHERE p.old_id ="
                                     " s.attachment_participant_id)".format(participants),
    }
    author = _foreign_user_filter("author_id", context)
    if author:
        overrides["author_id"] = author
    restored_chats = _copy(
        cursor, "chat_conversations", columns["chat_conversations"],
        staged["chat_conversations"], conversations, overrides,
    )
    cursor.execute("SELECT count(*) FROM {}".format(staged["chat_conversations"]))
    skipped_chats = cursor.fetchone()[0] - restored_chats
    #
    _copy(
        cursor, "chat_participant_mapping",
        [name for name in columns["chat_participant_mapping"] if name != "id"],
        staged["chat_participant_mapping"],
        overrides={
            "conversation_id": "c.new_id",
            "participant_id": "(SELECT p.new_id FROM {} p WHERE p.old_id = s.participant_id)".format(
                participants),
        },
        joins=" JOIN {} c ON c.old_id = s.conversation_id".format(conversations),
    )
    #
    # Messages of the restored conversations
    groups = _create_map(cursor, "chat_message_group")
    cursor.execute(
        "INSERT INTO {m} SELECT s.id, {new} FROM {s} s JOIN {c} c ON c.old_id = s.conversation_id"
        " WHERE NOT EXISTS (SELECT 1 FROM chat_message_group t WHERE t.uuid = s.uuid)".format(
            m=groups, s=staged["chat_message_group"], c=conversations,
            new=_new_id("chat_message_group"))
    )
    # Messages of re-mapped users keep the original author name for display
    imported_author = (
        "CASE WHEN f.old_id IS NOT NULL AND NOT (s.meta ? 'imported_author')"
        " THEN s.meta || jsonb_build_object('imported_author',"
        " jsonb_build_object('entity_name', 'user', 'name', f.name)) ELSE s.meta END"
    )
    messages = _copy(
        cursor, "chat_message_group", columns["chat_message_group"], staged["chat_message_group"], groups,
        overrides={
            "conversation_id": "(SELECT c.new_id FROM {} c WHERE c.old_id = s.conversation_id)".format(
                conversations),
            "author_participant_id": "(SELECT p.new_id FROM {} p WHERE p.old_id ="
                                     " s.author_participant_id)".format(participants),
            "sent_to_id": "(SELECT p.new_id FROM {} p WHERE p.old_id = s.sent_to_id)".format(participants),
            "reply_to_id": "(SELECT g.new_id FROM {} g WHERE g.old_id = s.reply_to_id)".format(groups),
            "meta": imported_author,
            "is_streaming": "false",
            "task_id": "NULL",
        },
        joins=" LEFT JOIN {} f ON f.old_id = s.author_participant_id".format(foreign),
    )
    #
    items = _create_map(cursor, "chat_message_items")
    cursor.execute(
        "INSERT INTO {m} SELECT s.id, {new} FROM {s} s JOIN {g} g ON g.old_id = s.message_group_id"
        " WHERE NOT EXISTS (SELECT 1 FROM chat_message_items t WHERE t.uuid = s.uuid)".format(
            m=items, s=staged["chat_message_items"], g=groups, new=_new_id("chat_message_items"))
    )
    _copy(
        cursor, "chat_message_items", columns["chat_message_items"], staged["chat_message_items"], items,
        overrides={
            "message_group_id": "(SELECT g.new_id FROM {} g WHERE g.old_id = s.message_group_id)".format(
                groups),
        },
    )
    for table in ("chat_messages_text", "chat_messages_canvas", "chat_messages_attachment"):
        overrides = {}
        if table == "chat_messages_attachment" and "artifacts" in existing:
            # The artifacts table is not part of the backup
            overrides["artifact_id"] = "(SELECT a.artifact_id FROM artifacts a" \
                                       " WHERE a.artifact_id = s.artifact_id LIMIT 1)"
        elif table == "chat_messages_attachment":
            overrides["artifact_id"] = "NULL"
        _copy(cursor, table, columns[table], staged[table], items, overrides)
    #
    versions = _create_map(cursor, "chat_canvas_versions")
    cursor.execute(
        "INSERT INTO {m} SELECT s.id, {new} FROM {s} s JOIN {i} i ON i.old_id = s.canvas_item_id".format(
            m=versions, s=staged["chat_canvas_versions"], i=items, new=_new_id("chat_canvas_versions"))
    )
    _copy(
        cursor, "chat_canvas_versions", columns["chat_canvas_versions"], staged["chat_canvas_versions"],
        versions,
        overrides={
            "canvas_item_id": "(SELECT i.new_id FROM {} i WHERE i.old_id = s.canvas_item_id)".format(items),
        },
    )
    _copy(
        cursor, "chat_canvas_version_authors",
        [name for name in columns["chat_canvas_version_authors"] if name != "id"],
        staged["chat_canvas_version_authors"],
        overrides={
            "canvas_version_id": "v.new_id",
            "participant_id": "(SELECT p.new_id FROM {} p WHERE p.old_id = s.participant_id)".format(
                participants),
        },
        joins=" JOIN {} v ON v.old_id = s.canvas_version_id".format(versions),
    )
    #
    cursor.execute(
        "SELECT a.id, a.bucket, a.name, a.content::text FROM chat_messages_attachment a"
        " JOIN {} m ON m.new_id = a.id ORDER BY a.id".format(items)
    )
    attachments = [
        {"id": row[0], "bucket": row[1], "name": row[2], "content": row[3]}
        for row in cursor.fetchall()
    ]
    #
    summary = {
        "restored": restored_chats,
        "skipped": skipped_chats,
        "messages": messages,
        "remapped_users": len(_foreign_names(cursor, foreign)),
    }
    return summary, attachments


def _foreign_names(cursor, foreign):
    cursor.execute("SELECT name FROM {}".format(foreign))
    return [row[0] for row in cursor.fetchall()]


def _replace_strings(value, replacements):
    if isinstance(value, str):
        for old, new in replacements:
            value = value.replace(old, new)
        return value
    if isinstance(value, list):
        return [_replace_strings(item, replacements) for item in value]
    if isinstance(value, dict):
        return {key: _replace_strings(item, replacements) for key, item in value.items()}
    return value


def relink_attachment(cursor, item, bucket, name):
    """ Point a restored attachment at the file uploaded for it """
    content = item["content"]
    if content and (bucket != item["bucket"] or name != item["name"]):
        content = json.dumps(_replace_strings(json.loads(content), (
            ("/{}/{}".format(item["bucket"], item["name"]), "/{}/{}".format(bucket, name)),
            ("Bucket: {}\nFilename: {}".format(item["bucket"], item["name"]),
             "Bucket: {}\nFilename: {}".format(bucket, name)),
        )))
    cursor.execute(
        "UPDATE chat_messages_attachment SET bucket = %s, name = %s, content = %s::json WHERE id = %s",
        (bucket, name, content, item["id"]),
    )


def replace_with_placeholder(cursor, item):
    """ Turn an attachment whose file is not available into a text message """
    file_name = item["name"].rsplit("/", 1)[-1]
    cursor.execute("DELETE FROM chat_messages_attachment WHERE id = %s", (item["id"],))
    cursor.execute(
        "UPDATE chat_message_items SET item_type = 'text_message',"
        " meta = meta || jsonb_build_object('restore_placeholder', true, 'original_name', %s::text)"
        " WHERE id = %s",
        (file_name, item["id"]),
    )
    cursor.execute(
        "INSERT INTO chat_messages_text (id, content) VALUES (%s, %s)",
        (item["id"], PLACEHOLDER_TEXT.format(file_name)),
    )


MAX_ZIP_ENTRIES = 200000


def open_backup_zip(spool, max_total_bytes):
    """ Open an uploaded backup archive and check it before anything is read

    Returns (archive, info, manifest). Entries with absolute or parent paths,
    an archive declaring more uncompressed data than allowed, or one missing
    its SQL part is refused.
    """
    import zipfile  # pylint: disable=C0415
    from .chat_backup import ZIP_INFO_NAME, ZIP_MANIFEST_NAME, ZIP_SQL_NAME
    #
    try:
        archive = zipfile.ZipFile(spool)  # pylint: disable=R1732
    except zipfile.BadZipFile as exc:
        raise ValueError("the backup archive is damaged") from exc
    #
    entries = archive.infolist()
    total = 0
    for entry in entries:
        name = entry.filename
        if name.startswith(("/", "\\")) or ".." in name.replace("\\", "/").split("/") \
                or entry.flag_bits & 0x1:
            archive.close()
            raise ValueError("the backup archive contains an unsafe entry: {}".format(name[:200]))
        total += entry.file_size
    #
    if len(entries) > MAX_ZIP_ENTRIES or total > max_total_bytes:
        archive.close()
        raise ValueError("the backup archive is larger than this setup allows")
    #
    names = {entry.filename for entry in entries}
    if ZIP_SQL_NAME not in names:
        archive.close()
        raise ValueError("the backup archive has no SQL backup")
    #
    def load(name):
        if name not in names:
            return {}
        try:
            value = json.loads(archive.read(name))
        except ValueError:
            return {}
        return value if isinstance(value, dict) else {}
    #
    return archive, load(ZIP_INFO_NAME), load(ZIP_MANIFEST_NAME)


def iter_zip_sql(archive):
    """ Re-readable byte stream over the SQL part of a backup archive """
    from .chat_backup import ZIP_SQL_NAME  # pylint: disable=C0415
    #
    def opener():
        with archive.open(ZIP_SQL_NAME) as source:
            while True:
                chunk = source.read(262144)
                if not chunk:
                    break
                yield chunk
    #
    return opener


def _free_name(name, taken):
    """ name, or name with a ' (n)' suffix before the extension, not in taken """
    if name not in taken:
        return name
    folder, _, base = name.rpartition("/")
    stem, dot, extension = base.rpartition(".")
    if not dot:
        stem, extension = base, ""
    index = 1
    while True:
        candidate = "{}{} ({}){}{}".format(
            folder + "/" if folder else "", stem, index, "." if dot else "", extension,
        )
        if candidate not in taken:
            return candidate
        index += 1


class AttachmentRestorer:  # pylint: disable=R0902
    """ Uploads the files of restored attachment messages and re-links them

    with_files=False only keeps the messages whose file the target bucket
    already has. Uploaded objects are removed again when the restore does not
    commit (dry run, or a failure afterwards).
    """

    def __init__(  # pylint: disable=R0913
            self, client, bucket, archive=None, manifest=None, with_files=False, retention_days=None,
    ):
        self.client = client
        self.bucket = bucket
        self.archive = archive
        self.retention_days = retention_days
        self.with_files = with_files and archive is not None
        self.files = {}
        for item in (manifest or {}).get("attachments") or []:
            if item.get("status") == "ok" and item.get("path"):
                self.files[(item.get("bucket"), item.get("name"))] = item
        self.listings = {}
        self.bucket_ready = False
        self.uploaded = []

    def _names(self, bucket):
        """ name -> size of the files a target bucket holds """
        if bucket not in self.listings:
            try:
                self.listings[bucket] = {
                    entry["name"]: entry["size"] for entry in self.client.list_files(bucket)
                }
            except Exception:  # pylint: disable=W0703
                self.listings[bucket] = {}
        return self.listings[bucket]

    def _upload(self, item):
        """ (bucket, name) the file was stored under, or None """
        record = self.files.get((item["bucket"], item["name"]))
        if record is None:
            return None
        taken = self._names(self.bucket)
        # The same file is already there (a restore into the project it came from)
        if taken.get(item["name"]) == record.get("size"):
            return self.bucket, item["name"]
        #
        content = self.archive.read(record["path"])
        name = _free_name(item["name"], taken)
        if not self.bucket_ready:
            if self.bucket not in self.client.list_bucket():
                self.client.create_bucket(
                    bucket=self.bucket, bucket_type="local", retention_days=self.retention_days,
                )
            self.bucket_ready = True
        self.client.upload_file(self.bucket, content, name)
        taken[name] = len(content)
        self.uploaded.append((self.bucket, name))
        return self.bucket, name

    def cleanup(self):
        for bucket, name in self.uploaded:
            try:
                self.client.remove_file(bucket, name)
            except Exception:  # pylint: disable=W0703
                pass
        self.uploaded = []

    def __call__(self, cursor, attachments, dry_run):
        summary = {"total": len(attachments), "uploaded": 0, "linked": 0, "failed": 0, "failed_names": []}
        uploads = {}
        #
        for item in attachments:
            key = (item["bucket"], item["name"])
            target = None
            try:
                if self.with_files:
                    if key not in uploads:
                        # A preview only checks the archive has the file
                        if dry_run:
                            uploads[key] = key if key in self.files else None
                        else:
                            uploads[key] = self._upload(item)
                        if uploads[key] is not None:
                            summary["uploaded"] += 1
                    target = uploads[key]
                elif item["name"] in self._names(item["bucket"]):
                    target = key
                    summary["linked"] += 1
            except Exception:  # pylint: disable=W0703
                target = None
            #
            if target is None:
                summary["failed"] += 1
                summary["failed_names"].append(item["name"].rsplit("/", 1)[-1])
                replace_with_placeholder(cursor, item)
            else:
                relink_attachment(cursor, item, target[0], target[1])
        #
        summary["failed_names"] = summary["failed_names"][:50]
        return summary
