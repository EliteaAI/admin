"""Integration tests for #6907 - backup and restore of chats against PostgreSQL.

A throwaway database is created next to the one in ELITEA_TEST_PG_DSN (the
user needs CREATEDB) and dropped afterwards. Two project schemas are built
from the chat DDL below, a backup of the source one is produced with
iter_project_backup_sql and applied to the target with restore_safe_backup.

    ELITEA_TEST_PG_DSN="postgresql://centry:changeme@localhost:5432/db" \\
        python tests/run_tests.py integration/test_6907_chat_backup_roundtrip.py

Skipped when the variable is not set.
"""
import importlib.util
import json
import os
import pathlib
import sys
import types
import uuid

import pytest

psycopg2 = pytest.importorskip("psycopg2")
from psycopg2 import sql as psql  # noqa: E402  pylint: disable=C0413


DSN = os.environ.get("ELITEA_TEST_PG_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="ELITEA_TEST_PG_DSN is not set")

UTILS_PATH = pathlib.Path(__file__).resolve().parents[2] / "utils"
PACKAGE = "_admin_utils_6907_it"

SOURCE = "p_901"
TARGET = "p_902"
SOURCE_ID = 901
TARGET_ID = 902

OWNER = 3        # takes the backup
MEMBER = 4       # another member of both projects
OUTSIDER = 5     # member of the source project only
RESTORER = 6     # restores into the target

# Chat tables as elitea_core creates them (columns, keys and FKs), plus the
# tables the participants and restore point at
DDL = """
CREATE TABLE {s}.applications (id serial PRIMARY KEY, name varchar NOT NULL);
CREATE TABLE {s}.elitea_tools (id serial PRIMARY KEY, name varchar NOT NULL);
CREATE TABLE {s}.chat_templates (id serial PRIMARY KEY, name varchar NOT NULL UNIQUE,
    participants jsonb NOT NULL DEFAULT '[]', is_default boolean NOT NULL DEFAULT false);
CREATE TABLE {s}.chat_participants (id serial PRIMARY KEY, uuid uuid NOT NULL UNIQUE,
    entity_name varchar NOT NULL, entity_meta jsonb NOT NULL, meta json NOT NULL);
CREATE TABLE {s}.chat_conversation_folders (id serial PRIMARY KEY, uuid uuid NOT NULL UNIQUE,
    name varchar NOT NULL, owner_id integer NOT NULL, meta jsonb NOT NULL,
    created_at timestamp NOT NULL DEFAULT now(), updated_at timestamp, position integer NOT NULL DEFAULT 0);
CREATE TABLE {s}.chat_conversations (id serial PRIMARY KEY, uuid uuid NOT NULL UNIQUE,
    name varchar NOT NULL, is_private boolean NOT NULL, author_id integer NOT NULL, meta jsonb NOT NULL,
    source varchar NOT NULL, instructions varchar,
    attachment_participant_id integer REFERENCES {s}.chat_participants(id),
    folder_id integer REFERENCES {s}.chat_conversation_folders(id),
    created_at timestamp NOT NULL DEFAULT now(), updated_at timestamp);
CREATE TABLE {s}.chat_participant_mapping (id serial PRIMARY KEY,
    conversation_id integer NOT NULL REFERENCES {s}.chat_conversations(id),
    participant_id integer NOT NULL REFERENCES {s}.chat_participants(id),
    entity_settings jsonb NOT NULL, created_at timestamp NOT NULL DEFAULT now(), updated_at timestamp,
    CONSTRAINT _participant_conversation_uc UNIQUE (participant_id, conversation_id));
CREATE TABLE {s}.chat_message_group (id serial PRIMARY KEY, uuid uuid NOT NULL UNIQUE,
    author_participant_id integer NOT NULL REFERENCES {s}.chat_participants(id),
    conversation_id integer NOT NULL REFERENCES {s}.chat_conversations(id),
    sent_to_id integer REFERENCES {s}.chat_participants(id),
    reply_to_id integer REFERENCES {s}.chat_message_group(id) ON DELETE SET NULL,
    meta jsonb NOT NULL, is_streaming boolean NOT NULL,
    created_at timestamp NOT NULL DEFAULT now(), updated_at timestamp, task_id varchar);
CREATE TABLE {s}.chat_message_items (id serial PRIMARY KEY, uuid uuid NOT NULL UNIQUE,
    item_type varchar NOT NULL, order_index integer NOT NULL, meta jsonb NOT NULL,
    created_at timestamp NOT NULL DEFAULT now(), updated_at timestamp,
    message_group_id integer NOT NULL REFERENCES {s}.chat_message_group(id) ON DELETE CASCADE);
CREATE TABLE {s}.chat_messages_text (content text NOT NULL,
    id integer PRIMARY KEY REFERENCES {s}.chat_message_items(id) ON DELETE CASCADE);
CREATE TABLE {s}.chat_messages_attachment (name varchar NOT NULL, bucket varchar NOT NULL,
    attachment_type varchar NOT NULL, content json, artifact_id uuid,
    id integer PRIMARY KEY REFERENCES {s}.chat_message_items(id) ON DELETE CASCADE);
CREATE TABLE {s}.chat_messages_canvas (name text NOT NULL, canvas_type varchar NOT NULL,
    id integer PRIMARY KEY REFERENCES {s}.chat_message_items(id) ON DELETE CASCADE);
CREATE TABLE {s}.chat_messages_context (context_data jsonb NOT NULL, context_type text,
    id integer PRIMARY KEY REFERENCES {s}.chat_message_items(id) ON DELETE CASCADE);
CREATE TABLE {s}.chat_canvas_versions (id serial PRIMARY KEY, code_language varchar,
    canvas_content text NOT NULL,
    canvas_item_id integer NOT NULL REFERENCES {s}.chat_messages_canvas(id) ON DELETE CASCADE,
    created_at timestamp NOT NULL DEFAULT now());
CREATE TABLE {s}.chat_canvas_version_authors (id serial PRIMARY KEY,
    participant_id integer NOT NULL REFERENCES {s}.chat_participants(id) ON DELETE CASCADE,
    canvas_version_id integer NOT NULL REFERENCES {s}.chat_canvas_versions(id) ON DELETE CASCADE,
    CONSTRAINT _participant_id_canvas_version_id_uc UNIQUE (participant_id, canvas_version_id));
CREATE TABLE {s}.chat_conversation_share_tokens (id serial PRIMARY KEY, token varchar NOT NULL UNIQUE,
    conversation_id integer NOT NULL REFERENCES {s}.chat_conversations(id) ON DELETE CASCADE,
    password_hash varchar);
CREATE TABLE {s}.chat_selected_conversations (id serial PRIMARY KEY, user_id integer NOT NULL,
    conversation_id integer NOT NULL REFERENCES {s}.chat_conversations(id) ON DELETE CASCADE);
CREATE TABLE {s}.chat_message_trace_step (id bigserial PRIMARY KEY,
    message_group_id integer NOT NULL REFERENCES {s}.chat_message_group(id) ON DELETE CASCADE,
    kind text NOT NULL);
"""


def _load_utils():
    if "pylon.core.tools" not in sys.modules:
        tools = types.ModuleType("pylon.core.tools")
        tools.log = types.SimpleNamespace(
            info=lambda *a, **k: None, warning=lambda *a, **k: None,
            error=lambda *a, **k: None, exception=lambda *a, **k: None,
        )
        sys.modules.setdefault("pylon", types.ModuleType("pylon"))
        sys.modules.setdefault("pylon.core", types.ModuleType("pylon.core"))
        sys.modules["pylon.core.tools"] = tools
    package = types.ModuleType(PACKAGE)
    package.__path__ = [str(UTILS_PATH)]
    sys.modules[PACKAGE] = package
    modules = {}
    for name in ("project_backup", "chat_backup", "chat_restore", "project_restore"):
        spec = importlib.util.spec_from_file_location(
            "{}.{}".format(PACKAGE, name), UTILS_PATH / "{}.py".format(name),
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        modules[name] = module
    return modules


MODULES = _load_utils()
cb = MODULES["chat_backup"]
cr = MODULES["chat_restore"]
pb = MODULES["project_backup"]
pr = MODULES["project_restore"]


@pytest.fixture(scope="module")
def database():
    name = "elitea_test_6907_{}".format(uuid.uuid4().hex[:8])
    admin = psycopg2.connect(DSN)
    admin.autocommit = True
    with admin.cursor() as cursor:
        cursor.execute(psql.SQL("CREATE DATABASE {}").format(psql.Identifier(name)))
    dsn = psycopg2.extensions.parse_dsn(DSN)
    dsn["dbname"] = name
    yield dsn
    with admin.cursor() as cursor:
        cursor.execute(psql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(psql.Identifier(name)))
    admin.close()


@pytest.fixture()
def connect(database):
    connections = []

    def opener():
        connection = psycopg2.connect(**database)
        connections.append(connection)
        return connection
    yield opener
    for connection in connections:
        connection.close()


def _build_schemas(connection):
    with connection.cursor() as cursor:
        for schema in (SOURCE, TARGET):
            cursor.execute("DROP SCHEMA IF EXISTS {} CASCADE".format(schema))
            cursor.execute("CREATE SCHEMA {}".format(schema))
            cursor.execute(DDL.format(s=schema))
    connection.commit()


def _insert(cursor, schema, table, row):
    columns = list(row)
    values = [json.dumps(v) if isinstance(v, (dict, list)) else v for v in row.values()]
    cursor.execute(
        "INSERT INTO {}.{} ({}) VALUES ({}) RETURNING id".format(
            schema, table, ", ".join(columns), ", ".join(["%s"] * len(columns)),
        ),
        values,
    )
    return cursor.fetchone()[0]


def _seed_source(connection):
    """ A team chat with an agent, canvas and attachments, the owner's and a
        member's private chat, a folder, a share token and a trace step """
    ids = {}
    with connection.cursor() as cursor:
        s = SOURCE
        ids["agent"] = _insert(cursor, s, "applications", {"name": "Helper"})
        ids["gone_agent"] = _insert(cursor, s, "applications", {"name": "Removed later"})
        participant = {}
        for key, entity_name, meta, entity_meta in (
                ("owner", "user", {"user_name": "owner@x"}, {"id": OWNER}),
                ("member", "user", {"user_name": "member@x"}, {"id": MEMBER}),
                ("outsider", "user", {"user_name": "outsider@x"}, {"id": OUTSIDER}),
                ("dummy", "dummy", {"name": "Alita"}, {}),
                ("agent", "application", {"name": "Helper"}, {"id": ids["agent"], "project_id": SOURCE_ID}),
                ("gone", "application", {"name": "Removed"}, {"id": 999, "project_id": SOURCE_ID}),
        ):
            participant[key] = _insert(cursor, s, "chat_participants", {
                "uuid": str(uuid.uuid4()), "entity_name": entity_name, "entity_meta": entity_meta, "meta": meta,
            })
        ids["participant"] = participant
        ids["folder"] = _insert(cursor, s, "chat_conversation_folders", {
            "uuid": str(uuid.uuid4()), "name": "Work", "owner_id": OWNER, "meta": {},
        })
        conversations = {}
        for key, private, author, folder in (
                ("team", False, OUTSIDER, ids["folder"]),
                ("own_private", True, OWNER, None),
                ("member_private", True, MEMBER, None),
        ):
            conversations[key] = _insert(cursor, s, "chat_conversations", {
                "uuid": str(uuid.uuid4()), "name": key, "is_private": private, "author_id": author,
                "meta": {"api_key": "sk-abcdefghijklmnopqrstuvwxyz"}, "source": "elitea", "folder_id": folder,
            })
        ids["conversation"] = conversations
        for conversation in conversations.values():
            for key in ("owner", "outsider", "agent", "gone"):
                _insert(cursor, s, "chat_participant_mapping", {
                    "conversation_id": conversation, "participant_id": participant[key], "entity_settings": {},
                })
        #
        team = conversations["team"]
        question = _insert(cursor, s, "chat_message_group", {
            "uuid": str(uuid.uuid4()), "author_participant_id": participant["outsider"],
            "conversation_id": team, "sent_to_id": participant["agent"], "meta": {}, "is_streaming": False,
        })
        answer = _insert(cursor, s, "chat_message_group", {
            "uuid": str(uuid.uuid4()), "author_participant_id": participant["agent"],
            "conversation_id": team, "reply_to_id": question, "meta": {"is_error": True, "error": "boom"},
            "is_streaming": True, "task_id": "task-1",
        })
        gone_answer = _insert(cursor, s, "chat_message_group", {
            "uuid": str(uuid.uuid4()), "author_participant_id": participant["gone"],
            "conversation_id": team, "reply_to_id": question, "meta": {}, "is_streaming": False,
        })
        ids["groups"] = [question, answer, gone_answer]

        def item(group, item_type, index):
            return _insert(cursor, s, "chat_message_items", {
                "uuid": str(uuid.uuid4()), "item_type": item_type, "order_index": index,
                "meta": {}, "message_group_id": group,
            })
        text = item(question, "text_message", 0)
        cursor.execute("INSERT INTO {}.chat_messages_text (id, content) VALUES (%s, %s)".format(s), (text, "Hi"))
        for index, name in enumerate(("c1/report.pdf", "c1/cat.png", "c1/lost.txt")):
            attachment = item(question, "attachment_message", index + 1)
            cursor.execute(
                "INSERT INTO {}.chat_messages_attachment (id, name, bucket, attachment_type, content)"
                " VALUES (%s, %s, 'attachments', 'document', %s)".format(s),
                (attachment, name, json.dumps([{"type": "text", "text": "Bucket: attachments\nFilename: " + name}])),
            )
        canvas = item(answer, "canvas_message", 0)
        cursor.execute(
            "INSERT INTO {}.chat_messages_canvas (id, name, canvas_type) VALUES (%s, 'code', 'code')".format(s),
            (canvas,),
        )
        version = _insert(cursor, s, "chat_canvas_versions", {"canvas_item_id": canvas, "canvas_content": "x = 1"})
        _insert(cursor, s, "chat_canvas_version_authors", {
            "participant_id": participant["agent"], "canvas_version_id": version,
        })
        context = item(answer, "context_message", 1)
        cursor.execute(
            "INSERT INTO {}.chat_messages_context (id, context_data) VALUES (%s, '{{}}')".format(s), (context,),
        )
        text = item(gone_answer, "text_message", 0)
        cursor.execute("INSERT INTO {}.chat_messages_text (id, content) VALUES (%s, %s)".format(s), (text, "Bye"))
        #
        for private in ("own_private", "member_private"):
            group = _insert(cursor, s, "chat_message_group", {
                "uuid": str(uuid.uuid4()), "author_participant_id": participant["owner"],
                "conversation_id": conversations[private], "meta": {}, "is_streaming": False,
            })
            text = item(group, "text_message", 0)
            cursor.execute(
                "INSERT INTO {}.chat_messages_text (id, content) VALUES (%s, %s)".format(s), (text, private),
            )
        #
        _insert(cursor, s, "chat_conversation_share_tokens", {
            "token": "share-token", "conversation_id": team, "password_hash": "hash",
        })
        _insert(cursor, s, "chat_selected_conversations", {"user_id": OWNER, "conversation_id": team})
        _insert(cursor, s, "chat_message_trace_step", {"message_group_id": answer, "kind": "tool"})
        # The target already has the agent under the same id
        _insert(cursor, TARGET, "applications", {"name": "Helper"})
    connection.commit()
    return ids


def _backup(connection, mode=cb.CHATS_WITHOUT_ATTACHMENTS):
    chats = {}
    if mode != cb.CHATS_NONE:
        with connection.cursor() as cursor:
            scope = cb.resolve_chat_scope(cursor, SOURCE, OWNER)
        connection.rollback()
        chats = {
            "included_tables": cb.CHAT_BACKUP_TABLES,
            "row_filters": cb.chat_row_filters(SOURCE, OWNER),
            "header_extra": {
                "chats_included": mode, "chats_count": scope["chats_count"],
                "attachments_count": len(scope["attachments"]),
            },
        }
    text = "".join(pb.iter_project_backup_sql(connection, SOURCE_ID, SOURCE, "Source", **chats))
    connection.rollback()
    return text


def _restore(connection, text, truncate=False, dry_run=False, restore_chats=cb.CHATS_WITHOUT_ATTACHMENTS,
             handler=None, target=TARGET, target_id=TARGET_ID, members=(OWNER, MEMBER, RESTORER)):
    header = pr.parse_header(text[:pr.HEADER_SCAN_BYTES])
    return pr.restore_safe_backup(
        connection, open_chunks=lambda: iter([text]), schema=target,
        truncate=truncate, dry_run=dry_run, denied_tables=pr.SAFE_RESTORE_DENIED_TABLES,
        owner_user_id=RESTORER, owner_project_id=target_id, source_project_id=SOURCE_ID,
        member_user_ids=list(members), backup_chats=header["chats_included"], restore_chats=restore_chats,
        chat_context={"restorer_id": RESTORER, "source_project_id": SOURCE_ID, "target_project_id": target_id},
        attachment_handler=handler,
    )


def _rows(connection, query, params=None):
    with connection.cursor() as cursor:
        cursor.execute(query, params)
        rows = cursor.fetchall()
    connection.rollback()
    return rows


def _count(connection, schema, table):
    return _rows(connection, "SELECT count(*) FROM {}.{}".format(schema, table))[0][0]


@pytest.fixture()
def seeded(connect):
    connection = connect()
    _build_schemas(connection)
    return connection, _seed_source(connection)


# ---------- backup ----------

def test_backup_without_chats_is_unchanged(seeded):
    connection, _ = seeded
    text = _backup(connection, cb.CHATS_NONE)
    assert "chat_conversations" not in pr.scan_backup_tables(lambda: iter([text]))
    assert "chats_included" not in text.split("BEGIN;")[0]
    assert pr.parse_header(text)["chats_included"] == cb.CHATS_NONE


def test_backup_with_chats_carries_only_allowed_tables_and_own_chats(seeded):
    connection, _ = seeded
    text = _backup(connection)
    tables = pr.scan_backup_tables(lambda: iter([text]))
    assert {"chat_conversations", "chat_message_group", "chat_messages_canvas"} <= tables
    assert not tables.intersection({
        "chat_conversation_share_tokens", "chat_selected_conversations", "chat_message_trace_step",
        "chat_messages_context",
    })
    header = pr.parse_header(text)
    assert header["chats_included"] == cb.CHATS_WITHOUT_ATTACHMENTS
    assert header["chats_count"] == 2
    assert header["attachments_count"] == 3
    assert "own_private" in text and "member_private" not in text
    assert "context_message" not in text
    assert "sk-abcdefghijklmnopqrstuvwxyz" not in text


def test_old_style_restore_refuses_chat_tables_from_a_forged_header(seeded):
    connection, _ = seeded
    text = _backup(connection).replace("-- chats_included: without_attachments\n", "")
    with pytest.raises(ValueError, match="not allowed"):
        _restore(connection, text)
    assert _count(connection, TARGET, "chat_conversations") == 0


# ---------- restore ----------

def test_restore_chats_merge_creates_everything_with_fresh_ids(seeded):
    connection, ids = seeded
    # The target already has a chat under the id the backup uses
    with connection.cursor() as cursor:
        dummy = _insert(cursor, TARGET, "chat_participants", {
            "uuid": str(uuid.uuid4()), "entity_name": "dummy", "entity_meta": {}, "meta": {"name": "Alita"},
        })
        existing = _insert(cursor, TARGET, "chat_conversations", {
            "uuid": str(uuid.uuid4()), "name": "existing", "is_private": False, "author_id": RESTORER,
            "meta": {}, "source": "elitea",
        })
        _insert(cursor, TARGET, "chat_message_group", {
            "uuid": str(uuid.uuid4()), "author_participant_id": dummy, "conversation_id": existing,
            "meta": {}, "is_streaming": False,
        })
    connection.commit()
    #
    summary = _restore(connection, _backup(connection))
    assert summary["chats"]["restored"] == 2
    assert summary["chats"]["skipped"] == 0
    assert summary["chats"]["messages"] == 4
    #
    names = {row[0]: row[1:] for row in _rows(
        connection, "SELECT name, author_id, is_private, folder_id IS NOT NULL FROM {}.chat_conversations".format(TARGET),
    )}
    assert set(names) == {"existing", "team", "own_private"}
    # The outsider is not a member of the target: the restoring user takes over
    assert names["team"] == (RESTORER, False, True)
    assert names["own_private"] == (OWNER, True, False)
    #
    team = _rows(connection, "SELECT id FROM {}.chat_conversations WHERE name = 'team'".format(TARGET))[0][0]
    groups = _rows(connection, (
        "SELECT g.id, p.entity_name, p.entity_meta, g.reply_to_id, g.is_streaming, g.task_id, g.meta"
        " FROM {s}.chat_message_group g JOIN {s}.chat_participants p ON p.id = g.author_participant_id"
        " WHERE g.conversation_id = %s ORDER BY g.id").format(s=TARGET), (team,))
    question, answer, gone = groups
    assert question[1] == "user" and question[2] == {"id": RESTORER}
    assert question[6]["imported_author"] == {"entity_name": "user", "name": "outsider@x"}
    assert answer[1] == "application" and answer[2] == {"id": 1, "project_id": TARGET_ID}
    assert answer[3] == question[0]
    assert answer[4] is False and answer[5] is None
    assert answer[6]["is_error"] is True
    # An agent the target does not have answers as the default assistant
    assert gone[1] == "dummy"
    #
    assert _count(connection, TARGET, "chat_canvas_versions") == 1
    assert _count(connection, TARGET, "chat_canvas_version_authors") == 1
    assert _count(connection, TARGET, "chat_messages_context") == 0
    assert _count(connection, TARGET, "chat_conversation_share_tokens") == 0
    # Sequences are past the restored ids, so new chats still get created
    with connection.cursor() as cursor:
        _insert(cursor, TARGET, "chat_conversations", {
            "uuid": str(uuid.uuid4()), "name": "new", "is_private": True, "author_id": OWNER,
            "meta": {}, "source": "elitea",
        })
    connection.rollback()
    assert ids


def test_restore_twice_skips_existing_chats(seeded):
    connection, _ = seeded
    text = _backup(connection)
    _restore(connection, text)
    summary = _restore(connection, text)
    assert summary["chats"] == dict(summary["chats"], restored=0, skipped=2, messages=0)
    assert _count(connection, TARGET, "chat_conversations") == 2
    assert _count(connection, TARGET, "chat_message_group") == 4


def test_restore_into_the_source_project_skips_chats_it_still_has(seeded):
    connection, _ = seeded
    text = _backup(connection)
    with connection.cursor() as cursor:
        cursor.execute("DELETE FROM {}.chat_conversation_share_tokens".format(SOURCE))
        cursor.execute("DELETE FROM {}.chat_selected_conversations".format(SOURCE))
        cursor.execute("DELETE FROM {}.chat_message_trace_step".format(SOURCE))
        cursor.execute(
            "DELETE FROM {s}.chat_message_items WHERE message_group_id IN (SELECT id FROM {s}.chat_message_group"
            " WHERE conversation_id = (SELECT id FROM {s}.chat_conversations WHERE name = 'own_private'))".format(
                s=SOURCE))
        cursor.execute(
            "DELETE FROM {s}.chat_message_group WHERE conversation_id ="
            " (SELECT id FROM {s}.chat_conversations WHERE name = 'own_private')".format(s=SOURCE))
        cursor.execute("DELETE FROM {s}.chat_participant_mapping WHERE conversation_id ="
                       " (SELECT id FROM {s}.chat_conversations WHERE name = 'own_private')".format(s=SOURCE))
        cursor.execute("DELETE FROM {}.chat_conversations WHERE name = 'own_private'".format(SOURCE))
    connection.commit()
    summary = _restore(connection, text, target=SOURCE, target_id=SOURCE_ID,
                       members=(OWNER, MEMBER, OUTSIDER, RESTORER))
    assert summary["chats"]["restored"] == 1
    assert summary["chats"]["skipped"] == 1
    # Participants already in the project are reused, not duplicated
    assert _count(connection, SOURCE, "chat_participants") == 6


def test_restore_replace_deletes_existing_chats(seeded):
    connection, _ = seeded
    with connection.cursor() as cursor:
        dummy = _insert(cursor, TARGET, "chat_participants", {
            "uuid": str(uuid.uuid4()), "entity_name": "dummy", "entity_meta": {}, "meta": {},
        })
        _insert(cursor, TARGET, "chat_conversations", {
            "uuid": str(uuid.uuid4()), "name": "existing", "is_private": True, "author_id": MEMBER,
            "meta": {}, "source": "elitea", "attachment_participant_id": dummy,
        })
    connection.commit()
    summary = _restore(connection, _backup(connection), truncate=True)
    assert "chat_conversations" in summary["truncated_tables"]
    assert {row[0] for row in _rows(connection, "SELECT name FROM {}.chat_conversations".format(TARGET))} == {
        "team", "own_private"}


def test_do_not_restore_chats_leaves_them_alone(seeded):
    connection, _ = seeded
    with connection.cursor() as cursor:
        _insert(cursor, TARGET, "chat_conversations", {
            "uuid": str(uuid.uuid4()), "name": "existing", "is_private": True, "author_id": MEMBER,
            "meta": {}, "source": "elitea",
        })
    connection.commit()
    summary = _restore(connection, _backup(connection), truncate=True, restore_chats=cb.CHATS_NONE)
    assert "chats" not in summary
    assert "chat_conversations" in summary["skipped_tables"]
    assert not set(summary["truncated_tables"]).intersection(cb.CHAT_BACKUP_TABLES)
    assert [row[0] for row in _rows(connection, "SELECT name FROM {}.chat_conversations".format(TARGET))] == [
        "existing"]


def test_preview_changes_nothing(seeded):
    connection, _ = seeded
    summary = _restore(connection, _backup(connection), dry_run=True)
    assert summary["dry_run"] is True
    assert summary["chats"]["restored"] == 2
    assert _count(connection, TARGET, "chat_conversations") == 0
    assert _count(connection, TARGET, "chat_participants") == 0


def test_attachments_are_relinked_or_replaced(seeded):
    connection, _ = seeded
    storage = type("Storage", (), {
        "list_files": lambda self, bucket: [{"name": "c1/report.pdf", "size": 3}],
    })()
    handler = cr.AttachmentRestorer(storage, "attachments", with_files=False)
    summary = _restore(connection, _backup(connection), handler=handler)
    assert summary["attachments"] == dict(summary["attachments"], total=3, linked=1, failed=2)
    rows = _rows(connection, (
        "SELECT i.item_type, t.content, a.name FROM {s}.chat_message_items i"
        " LEFT JOIN {s}.chat_messages_text t ON t.id = i.id"
        " LEFT JOIN {s}.chat_messages_attachment a ON a.id = i.id"
        " WHERE i.item_type IN ('attachment_message') OR i.meta ? 'restore_placeholder' ORDER BY i.order_index"
    ).format(s=TARGET))
    assert rows == [
        ("attachment_message", None, "c1/report.pdf"),
        ("text_message", "\U0001F4CE cat.png (file not available)", None),
        ("text_message", "\U0001F4CE lost.txt (file not available)", None),
    ]


def test_failure_rolls_back_chats_and_uploaded_files(seeded):
    connection, _ = seeded

    class Exploding(cr.AttachmentRestorer):
        cleaned = False

        def __call__(self, cursor, attachments, dry_run):
            raise RuntimeError("storage exploded")

        def cleanup(self):
            Exploding.cleaned = True

    with pytest.raises(RuntimeError, match="storage exploded"):
        _restore(connection, _backup(connection), handler=Exploding(None, "attachments"))
    assert Exploding.cleaned
    assert _count(connection, TARGET, "chat_conversations") == 0
