"""Unit tests for #6907 - project backup and restore of all chats.

Covers utils/chat_backup.py, utils/chat_restore.py and the chat parts of
utils/project_backup.py / utils/project_restore.py that need no database.
"""
import importlib.util
import io
import json
import pathlib
import sys
import types
import zipfile

import pytest


UTILS_PATH = pathlib.Path(__file__).resolve().parents[2] / "utils"
PACKAGE = "_admin_utils_6907"


def _load_utils():
    """Import the backup / restore utils without a running pylon"""
    if "pylon.core.tools" not in sys.modules:
        tools = types.ModuleType("pylon.core.tools")
        tools.log = types.SimpleNamespace(
            info=lambda *a, **k: None, warning=lambda *a, **k: None,
            error=lambda *a, **k: None, exception=lambda *a, **k: None,
        )
        sys.modules.setdefault("pylon", types.ModuleType("pylon"))
        sys.modules.setdefault("pylon.core", types.ModuleType("pylon.core"))
        sys.modules["pylon.core.tools"] = tools
    #
    package = types.ModuleType(PACKAGE)
    package.__path__ = [str(UTILS_PATH)]
    sys.modules[PACKAGE] = package
    #
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


# ---------- table selection ----------

def test_chat_tables_are_safe_mode_tables():
    assert cb.CHAT_BACKUP_TABLES <= set(pb.SAFE_MODE_EXCLUDED_TABLES)


@pytest.mark.parametrize("table", [
    "chat_conversation_share_tokens", "chat_selected_conversations", "chat_message_trace_step",
    "chat_conversation_summaries", "chat_messages_context",
])
def test_security_and_derived_chat_tables_stay_excluded(table):
    assert table not in cb.CHAT_BACKUP_TABLES
    assert table in pr.SAFE_RESTORE_DENIED_TABLES


def test_row_filters_cover_every_chat_table():
    filters = cb.chat_row_filters("p_3", 7)
    assert set(filters) == set(cb.CHAT_BACKUP_TABLES)


def test_scope_keeps_team_chats_and_own_private_ones():
    sql = cb.conversation_scope_sql("p_3", 7)
    assert "not is_private or author_id = 7" in sql
    assert '"p_3".chat_conversations' in sql


def test_scope_user_id_is_an_integer():
    with pytest.raises(ValueError):
        cb.conversation_scope_sql("p_3", "1 or true")


def test_message_items_filter_skips_context_items():
    assert "item_type <> 'context_message'" in cb.chat_row_filters("p_3", 7)["chat_message_items"]


# ---------- header ----------

def _header(extra=None):
    return pb._header(  # pylint: disable=W0212
        3, "Team", "p_3", "2026-10-16T00:00:00+00:00", True, ["applications"], [], {}, extra,
    )


def test_header_carries_chat_lines():
    parsed = pr.parse_header(_header({
        "chats_included": cb.CHATS_WITH_ATTACHMENTS, "chats_count": 42, "attachments_count": 118,
    }))
    assert parsed["chats_included"] == cb.CHATS_WITH_ATTACHMENTS
    assert parsed["chats_count"] == 42
    assert parsed["attachments_count"] == 118
    assert parsed["project_id"] == 3


def test_old_backup_header_reads_as_no_chats():
    assert pr.parse_header(_header())["chats_included"] == cb.CHATS_NONE


def test_unknown_chats_value_reads_as_no_chats():
    assert pr.parse_header(_header({"chats_included": "everything"}))["chats_included"] == cb.CHATS_NONE


# ---------- summary / sizes ----------

def test_attach_file_sizes_marks_missing_files():
    attachments = [{"bucket": "attachments", "name": "a/1.png"}, {"bucket": "attachments", "name": "a/2.png"}]
    cb.attach_file_sizes(attachments, lambda bucket: [{"name": "a/1.png", "size": 10}])
    assert attachments[0] == {"bucket": "attachments", "name": "a/1.png", "size": 10, "status": "ok"}
    assert attachments[1]["status"] == cb.ATTACHMENT_MISSING
    summary = cb.summarize({"chats_count": 2, "attachments": attachments})
    assert summary == {
        "chats_count": 2, "attachments_count": 2, "attachments_size": 10, "missing_attachments": 1,
    }


def test_attach_file_sizes_survives_a_broken_bucket():
    def fail(bucket):
        raise RuntimeError("no bucket")
    attachments = cb.attach_file_sizes([{"bucket": "x", "name": "y"}], fail)
    assert attachments[0]["status"] == cb.ATTACHMENT_MISSING


# ---------- archive ----------

FILES = {("attachments", "c1/report.pdf"): b"%PDF-1.7 report", ("attachments", "c1/cat.png"): b"\x89PNG cat"}


def _build_zip(attachments, read_file=None):
    info = cb.make_info(3, "Team", {"id": 1, "name": "Admin"}, cb.CHATS_WITH_ATTACHMENTS, {
        "chats_count": 1, "attachments": attachments,
    })
    sql = [_header({"chats_included": cb.CHATS_WITH_ATTACHMENTS}).encode(), b"INSERT INTO x VALUES (1);\n"]
    data = b"".join(cb.iter_backup_zip(
        info, iter(sql), attachments, read_file or (lambda bucket, name: FILES[(bucket, name)]),
    ))
    return info, data


def test_zip_layout_and_manifest():
    attachments = [{"bucket": b, "name": n, "size": len(c), "status": "ok"} for (b, n), c in FILES.items()]
    _, data = _build_zip(attachments)
    archive = zipfile.ZipFile(io.BytesIO(data))
    names = archive.namelist()
    assert names[0] == cb.ZIP_INFO_NAME
    assert names[1] == cb.ZIP_SQL_NAME
    assert names[-1] == cb.ZIP_MANIFEST_NAME
    assert archive.read("attachments/attachments/c1/cat.png") == FILES[("attachments", "c1/cat.png")]
    manifest = json.loads(archive.read(cb.ZIP_MANIFEST_NAME))
    assert manifest["chats_included"] == cb.CHATS_WITH_ATTACHMENTS
    assert manifest["missing_attachments"] == 0
    assert all(item["checksum"] and item["status"] == "ok" for item in manifest["attachments"])
    assert b"INSERT INTO x" in archive.read(cb.ZIP_SQL_NAME)


def test_zip_lists_unreadable_files_as_missing():
    def read_file(bucket, name):
        if name == "c1/cat.png":
            raise FileNotFoundError(name)
        return FILES[(bucket, name)]
    attachments = [{"bucket": b, "name": n, "size": 1, "status": "ok"} for (b, n) in FILES]
    attachments.append({"bucket": "attachments", "name": "gone.txt", "status": cb.ATTACHMENT_MISSING})
    _, data = _build_zip(attachments, read_file)
    archive = zipfile.ZipFile(io.BytesIO(data))
    manifest = json.loads(archive.read(cb.ZIP_MANIFEST_NAME))
    statuses = {item["name"]: item["status"] for item in manifest["attachments"]}
    assert statuses == {"c1/report.pdf": "ok", "c1/cat.png": "missing", "gone.txt": "missing"}
    assert manifest["missing_attachments"] == 2
    assert "attachments/attachments/c1/cat.png" not in archive.namelist()


def test_zip_info_is_readable_from_the_first_bytes():
    info, data = _build_zip([])
    assert cb.is_zip(data)
    assert cb.read_zip_info(data[:4096]) == info


def test_read_zip_info_refuses_other_archives():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("readme.txt", "hi")
    assert cb.read_zip_info(buffer.getvalue()) is None
    assert cb.read_zip_info(b"-- ELITEA project backup") is None


def _spool(entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    buffer.seek(0)
    return buffer


def test_open_backup_zip_reads_info_and_manifest():
    attachments = [{"bucket": b, "name": n, "size": len(c), "status": "ok"} for (b, n), c in FILES.items()]
    info, data = _build_zip(attachments)
    archive, read_info, manifest = cr.open_backup_zip(io.BytesIO(data), 10 ** 9)
    assert read_info == info
    assert len(manifest["attachments"]) == 2
    sql = b"".join(cr.iter_zip_sql(archive)())
    assert sql.startswith(b"--\n-- ELITEA project backup")


@pytest.mark.parametrize("name", ["../evil.sql", "/etc/passwd", "attachments/../../x"])
def test_open_backup_zip_refuses_path_traversal(name):
    with pytest.raises(ValueError, match="unsafe entry"):
        cr.open_backup_zip(_spool({cb.ZIP_SQL_NAME: "x", name: "x"}), 10 ** 9)


def test_open_backup_zip_refuses_oversized_archives():
    with pytest.raises(ValueError, match="larger"):
        cr.open_backup_zip(_spool({cb.ZIP_SQL_NAME: "x" * 2048}), 1024)


def test_open_backup_zip_requires_the_sql_part():
    with pytest.raises(ValueError, match="no SQL backup"):
        cr.open_backup_zip(_spool({"info.json": "{}"}), 10 ** 9)


def test_open_backup_zip_refuses_garbage():
    with pytest.raises(ValueError, match="damaged"):
        cr.open_backup_zip(io.BytesIO(b"PK\x03\x04 not really"), 10 ** 9)


# ---------- attachment restore helpers ----------

def test_free_name_suffixes_before_the_extension():
    taken = {"c1/report.pdf", "c1/report (1).pdf"}
    assert cr._free_name("c1/report.pdf", taken) == "c1/report (2).pdf"  # pylint: disable=W0212
    assert cr._free_name("c1/new.pdf", taken) == "c1/new.pdf"  # pylint: disable=W0212
    assert cr._free_name("README", {"README"}) == "README (1)"  # pylint: disable=W0212


class RecordingCursor:
    def __init__(self):
        self.executed = []

    def execute(self, sql, params=None):
        self.executed.append((sql, params))


def test_relink_rewrites_file_references_in_content():
    cursor = RecordingCursor()
    content = json.dumps([
        {"type": "image_url", "image_url": {"url": "filepath:/attachments/c1/cat.png"}},
        {"type": "text", "text": "Bucket: attachments\nFilename: c1/cat.png\n..."},
    ])
    item = {"id": 5, "bucket": "attachments", "name": "c1/cat.png", "content": content}
    cr.relink_attachment(cursor, item, "chat-files", "c1/cat (1).png")
    sql, params = cursor.executed[0]
    assert "UPDATE chat_messages_attachment" in sql
    assert params[0:2] == ("chat-files", "c1/cat (1).png")
    rewritten = json.loads(params[2])
    assert rewritten[0]["image_url"]["url"] == "filepath:/chat-files/c1/cat (1).png"
    assert "Bucket: chat-files\nFilename: c1/cat (1).png" in rewritten[1]["text"]
    assert params[3] == 5


def test_placeholder_turns_the_item_into_text():
    cursor = RecordingCursor()
    cr.replace_with_placeholder(cursor, {"id": 9, "bucket": "attachments", "name": "c1/report.pdf"})
    statements = [sql for sql, _ in cursor.executed]
    assert statements[0].startswith("DELETE FROM chat_messages_attachment")
    assert "item_type = 'text_message'" in statements[1]
    assert cursor.executed[2][1] == (9, "\U0001F4CE report.pdf (file not available)")


class FakeStorage:
    def __init__(self, files=None, fail=()):
        self.files = dict(files or {})
        self.fail = set(fail)
        self.buckets = {bucket for bucket, _ in self.files}
        self.removed = []

    def list_files(self, bucket):
        return [{"name": name, "size": len(data)} for (b, name), data in self.files.items() if b == bucket]

    def list_bucket(self):
        return sorted(self.buckets)

    def create_bucket(self, bucket, bucket_type=None, retention_days=None):
        self.buckets.add(bucket)

    def upload_file(self, bucket, content, name):
        if name in self.fail:
            raise RuntimeError("storage is down")
        self.files[(bucket, name)] = content

    def remove_file(self, bucket, name):
        self.removed.append((bucket, name))
        self.files.pop((bucket, name), None)


def _restorer(storage, with_files=True):
    attachments = [{"bucket": b, "name": n, "size": len(c), "status": "ok"} for (b, n), c in FILES.items()]
    _, data = _build_zip(attachments)
    archive, _, manifest = cr.open_backup_zip(io.BytesIO(data), 10 ** 9)
    return cr.AttachmentRestorer(storage, "attachments", archive, manifest, with_files=with_files)


def _items():
    return [
        {"id": 1, "bucket": "attachments", "name": "c1/report.pdf", "content": None},
        {"id": 2, "bucket": "attachments", "name": "c1/cat.png", "content": None},
        {"id": 3, "bucket": "attachments", "name": "c1/report.pdf", "content": None},
        {"id": 4, "bucket": "attachments", "name": "c1/not-in-archive.txt", "content": None},
    ]


def test_restorer_uploads_each_file_once_and_renames_on_conflict():
    storage = FakeStorage({("attachments", "c1/cat.png"): b"another cat with a different size"})
    restorer = _restorer(storage)
    cursor = RecordingCursor()
    summary = restorer(cursor, _items(), dry_run=False)
    assert summary["uploaded"] == 2
    assert summary["failed"] == 1
    assert summary["failed_names"] == ["not-in-archive.txt"]
    assert storage.files[("attachments", "c1/cat (1).png")] == FILES[("attachments", "c1/cat.png")]
    assert storage.files[("attachments", "c1/cat.png")] == b"another cat with a different size"
    linked = {params[3]: params[1] for sql, params in cursor.executed if sql.startswith("UPDATE chat_messages_attachment")}
    assert linked == {1: "c1/report.pdf", 2: "c1/cat (1).png", 3: "c1/report.pdf"}


def test_restorer_reuses_the_same_file_already_in_the_bucket():
    storage = FakeStorage({("attachments", "c1/cat.png"): FILES[("attachments", "c1/cat.png")]})
    restorer = _restorer(storage)
    restorer(RecordingCursor(), _items()[1:2], dry_run=False)
    assert restorer.uploaded == []
    assert ("attachments", "c1/cat (1).png") not in storage.files


def test_restorer_dry_run_uploads_nothing():
    storage = FakeStorage()
    summary = _restorer(storage)(RecordingCursor(), _items(), dry_run=True)
    assert storage.files == {}
    assert summary["uploaded"] == 2
    assert summary["failed"] == 1


def test_restorer_cleanup_removes_uploaded_files():
    storage = FakeStorage()
    restorer = _restorer(storage)
    restorer(RecordingCursor(), _items(), dry_run=False)
    restorer.cleanup()
    assert sorted(storage.removed) == [("attachments", "c1/cat.png"), ("attachments", "c1/report.pdf")]


def test_restorer_upload_failure_becomes_a_placeholder():
    storage = FakeStorage(fail={"c1/cat.png"})
    cursor = RecordingCursor()
    summary = _restorer(storage)(cursor, _items()[:2], dry_run=False)
    assert summary["failed_names"] == ["cat.png"]
    assert any(sql.startswith("DELETE FROM chat_messages_attachment") and params == (2,)
               for sql, params in cursor.executed)


def test_restorer_without_files_only_links_existing_ones():
    storage = FakeStorage({("attachments", "c1/report.pdf"): b"x"})
    restorer = cr.AttachmentRestorer(storage, "attachments", with_files=False)
    summary = restorer(RecordingCursor(), _items(), dry_run=False)
    assert summary == {
        "total": 4, "uploaded": 0, "linked": 2, "failed": 2,
        "failed_names": ["cat.png", "not-in-archive.txt"],
    }
    assert storage.files == {("attachments", "c1/report.pdf"): b"x"}
