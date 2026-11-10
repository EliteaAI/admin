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

""" Project backup: the stored objects behind the skill version files

The skill_version_files rows travel in the SQL backup like any other table;
their bytes live in the project's 'skill-files' bucket under the sha256 of the
content. A backup of a project with skill files is a ZIP that also carries:

    skill-files/<sha256>       - every object the rows reference, stored
    skill-files-manifest.json  - every hash, its size and whether it was stored
"""

import json
import hashlib
from enum import Enum

from pylon.core.tools import log  # pylint: disable=E0611,E0401


SKILL_FILES_TABLE = "skill_version_files"
SKILL_FILES_BUCKET = "skill-files"

# The same lock elitea_core takes around every write of skill file rows
# (skill_utils.SKILL_FILE_WRITE_LOCK); its deletes and sweep back off while it is held
SKILL_FILE_WRITE_LOCK = "SELECT pg_advisory_xact_lock_shared(hashtext('skill-files'), %s)"

ZIP_SKILL_FILES_DIR = "skill-files/"
ZIP_SKILL_FILES_MANIFEST_NAME = "skill-files-manifest.json"

SKILL_FILES_FORMAT_VERSION = "1"


class SkillFilesOption(str, Enum):
    """ Whether a safe backup carries the stored skill files """
    ALL = "all"
    NONE = "none"


SKILL_FILE_OK = "ok"
SKILL_FILE_MISSING = "missing"

MAX_REPORTED_PATHS = 50


def _quote(identifier):
    return '"{}"'.format(str(identifier).replace('"', '""'))


def skill_file_path(sha256):
    """ Archive member holding the object stored under sha256 """
    return "{}{}".format(ZIP_SKILL_FILES_DIR, sha256)


def begin_backup_snapshot(connection, project_id):
    """ Read the whole safe backup from one snapshot, with the project's skill file deletes held off
        until the SQL part ends, so every dumped file row keeps its object """
    connection.rollback()
    with connection.cursor() as cursor:
        cursor.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        cursor.execute(SKILL_FILE_WRITE_LOCK, (project_id,))


def resolve_skill_files(cursor, schema):
    """ Distinct hashes the schema's skill version files reference, with their size """
    cursor.execute(
        "select 1 from information_schema.tables where table_schema = %s and table_name = %s",
        (schema, SKILL_FILES_TABLE),
    )
    if cursor.fetchone() is None:
        return []
    #
    cursor.execute(
        "select sha256, min(size) from {}.{} group by sha256 order by sha256".format(
            _quote(schema), _quote(SKILL_FILES_TABLE),
        )
    )
    return [{"sha256": sha256, "size": size} for sha256, size in cursor.fetchall()]


def summarize_skill_files(files):
    """ Count and total size of the objects a backup carries """
    return {
        "skill_files_count": len(files),
        "skill_files_size": sum(item.get("size") or 0 for item in files),
    }


def _read_verified(read_content, sha256):
    """ Object content when it is readable and still hashes to its key, else None """
    try:
        content = read_content(sha256)
    except Exception:  # pylint: disable=W0703
        return None
    if content is None or hashlib.sha256(content).hexdigest() != sha256:
        return None
    return content


def iter_skill_file_members(files, read_content):
    """ Yield (archive name, bytes) for every readable object, then the skill files manifest """
    records = []
    for item in files:
        record = {"sha256": item["sha256"], "size": item.get("size") or 0}
        content = _read_verified(read_content, item["sha256"])
        if content is None:
            record["status"] = SKILL_FILE_MISSING
        else:
            record.update({"status": SKILL_FILE_OK, "size": len(content)})
            yield skill_file_path(item["sha256"]), content
        records.append(record)
    #
    manifest = {
        "format_version": SKILL_FILES_FORMAT_VERSION,
        "bucket": SKILL_FILES_BUCKET,
        "files_count": len(records),
        "missing_files": sum(1 for record in records if record["status"] == SKILL_FILE_MISSING),
        "files": records,
    }
    yield ZIP_SKILL_FILES_MANIFEST_NAME, json.dumps(manifest).encode("utf-8")


def read_skill_files_manifest(archive):
    """ The skill files manifest of an opened backup archive, {} when it has none """
    if archive is None or ZIP_SKILL_FILES_MANIFEST_NAME not in archive.namelist():
        return {}
    try:
        manifest = json.loads(archive.read(ZIP_SKILL_FILES_MANIFEST_NAME))
    except ValueError:
        return {}
    return manifest if isinstance(manifest, dict) else {}


def restore_summary_counts(summary):
    """ The skill files restore summary without the paths, for the log """
    return {key: value for key, value in (summary or {}).items() if key != "missing_paths"}


class SkillFileRestorer:
    """ Gives the target bucket every object the target's skill version files reference

    Runs inside the restore transaction, before the rows commit, over every row
    of the target table: an object counts as stored only at the size its rows
    give. One the bucket lacks is uploaded from the archive when the archive has
    bytes that hash to it; otherwise its rows are kept and reported. Objects a
    restore uploads and then does not commit are left to elitea_core's sweep, as
    core leaves those of its own failed writes.
    """

    def __init__(self, open_client, archive=None):
        self.open_client = open_client
        self.client = None
        self.archive = archive
        self.members = frozenset(
            name for name in (archive.namelist() if archive is not None else ())
            if name.startswith(ZIP_SKILL_FILES_DIR)
        )

    def _stored_sizes(self):
        """ name -> size of the target bucket's objects, None when the bucket does not exist yet """
        self.client = self.open_client()
        if SKILL_FILES_BUCKET not in self.client.list_bucket():
            return None
        return {entry["name"]: entry["size"] for entry in self.client.list_files(SKILL_FILES_BUCKET)}

    def _archived_content(self, sha256):
        """ Archive bytes for sha256 when the archive has them and they hash to it, else None """
        name = skill_file_path(sha256)
        if name not in self.members:
            return None
        content = self.archive.read(name)
        return content if hashlib.sha256(content).hexdigest() == sha256 else None

    def _referenced(self, cursor):
        """ sha256 -> (size, paths) of the target's skill version files """
        cursor.execute(
            "SELECT sha256, size, path FROM {} ORDER BY sha256, path".format(_quote(SKILL_FILES_TABLE))
        )
        referenced = {}
        for sha256, size, path in cursor.fetchall():
            referenced.setdefault(sha256, (size, []))[1].append(path)
        return referenced

    def __call__(self, cursor, dry_run):
        """ Upload the referenced objects the bucket lacks from the archive, return a summary """
        referenced = self._referenced(cursor)
        summary = {
            "total": len(referenced), "present": 0, "uploaded": 0, "missing": 0,
            "missing_paths": [], "unchecked": False,
        }
        if not referenced:
            return summary
        #
        try:
            stored = self._stored_sizes()
        except Exception as exc:  # pylint: disable=W0703
            if self.members:
                raise
            log.warning("project_restore: could not list the skill files bucket, files left unchecked: %s", exc)
            summary["unchecked"] = True
            return summary
        #
        missing_paths = []
        for sha256, (size, paths) in referenced.items():
            if stored is not None and stored.get(sha256) == size:
                summary["present"] += 1
                continue
            content = self._archived_content(sha256)
            if content is None:
                summary["missing"] += 1
                missing_paths.extend(paths)
                continue
            if not dry_run:
                if stored is None:
                    self.client.create_bucket(bucket=SKILL_FILES_BUCKET, bucket_type="system")
                    stored = {}
                self.client.upload_file(SKILL_FILES_BUCKET, content, sha256)
                stored[sha256] = len(content)
            summary["uploaded"] += 1
        #
        summary["missing_paths"] = sorted(missing_paths)[:MAX_REPORTED_PATHS]
        return summary
