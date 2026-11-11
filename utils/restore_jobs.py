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

""" Project restore jobs: state of restores running in a forked task

The row is the only state shared between the pod that took the upload, the
forked process applying it and any pod a status poll lands on. At most one
queued / running job per project is enforced by a partial unique index.
"""

import json
import uuid

import psycopg2  # pylint: disable=E0401


TABLE = "admin_project_restore_job"

STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_DONE = "done"
STATUS_FAILED = "failed"
ACTIVE_STATUSES = (STATUS_QUEUED, STATUS_RUNNING)

STALE_ERROR = "restore process stopped before it finished"

COLUMNS = (
    "id", "project_id", "user_id", "mode", "status", "options", "artifact", "result",
    "error", "status_code", "instance", "task_id",
    "created_at", "started_at", "finished_at", "heartbeat_at",
)

DDL = """
CREATE TABLE IF NOT EXISTS {table} (
    id varchar(36) PRIMARY KEY,
    project_id integer NOT NULL,
    user_id integer,
    mode varchar(16) NOT NULL,
    status varchar(16) NOT NULL,
    options jsonb NOT NULL DEFAULT '{{}}',
    artifact jsonb,
    result jsonb,
    error text,
    status_code integer,
    instance varchar(256),
    task_id varchar(128),
    created_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    finished_at timestamptz,
    heartbeat_at timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS {prefix}_active_project
    ON {table} (project_id) WHERE status IN ('queued', 'running');
CREATE INDEX IF NOT EXISTS {prefix}_finished_at ON {table} (finished_at);
"""


class RestoreInProgress(Exception):
    """ The project already has a queued or running restore """

    def __init__(self, job_id):
        super().__init__("a restore is already in progress for this project")
        self.job_id = job_id


def _quote(identifier):
    return '"{}"'.format(str(identifier).replace('"', '""'))


def _qualified(schema):
    return "{}.{}".format(_quote(schema), _quote(TABLE))


def ensure_table(connection, schema):
    """ Create the job table and its indexes when missing """
    with connection.cursor() as cursor:
        cursor.execute(DDL.format(table=_qualified(schema), prefix=TABLE))
    connection.commit()


def _row(record):
    if record is None:
        return None
    job = dict(zip(COLUMNS, record))
    for key in ("created_at", "started_at", "finished_at", "heartbeat_at"):
        if job[key] is not None:
            job[key] = job[key].isoformat()
    return job


class JobStore:
    """ Job rows over short autocommitted statements

    connect() returns a DB-API connection; release(connection), when given,
    hands it back after every statement (a pooled one), otherwise it is kept.
    """

    def __init__(self, connect, schema, release=None):
        self.connect = connect
        self.release = release
        self.table = _qualified(schema)

    def _execute(self, sql, params=(), fetch=None):
        connection = self.connect()
        try:
            with connection.cursor() as cursor:
                cursor.execute(sql.format(table=self.table), params)
                if fetch == "one":
                    value = cursor.fetchone()
                elif fetch == "all":
                    value = cursor.fetchall()
                else:
                    value = cursor.rowcount
            connection.commit()
            return value
        except Exception:
            connection.rollback()
            raise
        finally:
            if self.release is not None:
                self.release(connection)

    def create(self, project_id, user_id, mode, options, artifact, instance):
        job_id = str(uuid.uuid4())
        try:
            record = self._execute(
                "INSERT INTO {table} (id, project_id, user_id, mode, status, options, artifact, instance)"
                " VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s)"
                " RETURNING " + ", ".join(COLUMNS),
                (job_id, project_id, user_id, mode, STATUS_QUEUED,
                 json.dumps(options or {}), json.dumps(artifact), instance),
                fetch="one",
            )
        except psycopg2.errors.UniqueViolation:  # pylint: disable=E1101
            active = self.active(project_id)
            raise RestoreInProgress(active["id"] if active else None) from None
        return _row(record)

    def get(self, job_id, project_id=None):
        sql = "SELECT " + ", ".join(COLUMNS) + " FROM {table} WHERE id = %s"
        params = [job_id]
        if project_id is not None:
            sql += " AND project_id = %s"
            params.append(project_id)
        return _row(self._execute(sql, tuple(params), fetch="one"))

    def active(self, project_id):
        return _row(self._execute(
            "SELECT " + ", ".join(COLUMNS) + " FROM {table}"
            " WHERE project_id = %s AND status IN %s",
            (project_id, ACTIVE_STATUSES), fetch="one",
        ))

    def attach_task(self, job_id, task_id):
        self._execute("UPDATE {table} SET task_id = %s WHERE id = %s", (task_id, job_id))

    def start(self, job_id, task_id=None):
        """ Mark the job running, False when it is no longer queued """
        return self._execute(
            "UPDATE {table} SET status = %s, task_id = COALESCE(%s, task_id),"
            " started_at = now(), heartbeat_at = now() WHERE id = %s AND status = %s",
            (STATUS_RUNNING, task_id, job_id, STATUS_QUEUED),
        ) > 0

    def heartbeat(self, job_id):
        self._execute(
            "UPDATE {table} SET heartbeat_at = now() WHERE id = %s AND status = %s",
            (job_id, STATUS_RUNNING),
        )

    def finish(self, job_id, result, status_code=200):
        # Only an active job finishes: a reaped one stays failed
        self._execute(
            "UPDATE {table} SET status = %s, result = %s::jsonb, status_code = %s,"
            " finished_at = now() WHERE id = %s AND status IN %s",
            (STATUS_DONE, json.dumps(result), status_code, job_id, ACTIVE_STATUSES),
        )

    def fail(self, job_id, error, status_code=500, body=None):
        self._execute(
            "UPDATE {table} SET status = %s, error = %s, status_code = %s, result = %s::jsonb,"
            " finished_at = now() WHERE id = %s AND status IN %s",
            (STATUS_FAILED, error, status_code, json.dumps(body), job_id, ACTIVE_STATUSES),
        )

    def instance_jobs(self, instance):
        """ Active jobs started by this instance """
        rows = self._execute(
            "SELECT " + ", ".join(COLUMNS) + " FROM {table} WHERE instance = %s AND status IN %s",
            (instance, ACTIVE_STATUSES), fetch="all",
        )
        return [_row(row) for row in rows or []]

    def fail_instance_jobs(self, instance):
        """ Jobs a restarted pod was running can not finish any more """
        return self._execute(
            "UPDATE {table} SET status = %s, error = %s, status_code = 500, finished_at = now()"
            " WHERE instance = %s AND status IN %s",
            (STATUS_FAILED, STALE_ERROR, instance, ACTIVE_STATUSES),
        )

    def reap(self, stale_after_seconds, retention_days):
        """ Fail jobs whose process went silent, delete finished ones past retention """
        failed = self._execute(
            "UPDATE {table} SET status = %s, error = %s, status_code = 500, finished_at = now()"
            " WHERE status IN %s"
            " AND COALESCE(heartbeat_at, created_at) < now() - make_interval(secs => %s)",
            (STATUS_FAILED, STALE_ERROR, ACTIVE_STATUSES, stale_after_seconds),
        )
        deleted = self._execute(
            "DELETE FROM {table} WHERE status NOT IN %s"
            " AND finished_at < now() - make_interval(days => %s)",
            (ACTIVE_STATUSES, retention_days),
        )
        return {"failed": failed, "deleted": deleted}


def public_view(job):
    """ What the status endpoint returns: the response body a synchronous restore had """
    view = {
        "ok": job["status"] != STATUS_FAILED,
        "job_id": job["id"],
        "status": job["status"],
        "artifact": job["artifact"],
        "created_at": job["created_at"],
        "started_at": job["started_at"],
        "finished_at": job["finished_at"],
    }
    if job["status"] == STATUS_DONE:
        view["result"] = job["result"]
    if job["status"] == STATUS_FAILED:
        body = job["result"] or {}
        view.update({key: value for key, value in body.items() if key not in ("ok", "job_id", "status")})
        view["error"] = body.get("error") or job["error"]
    return view
