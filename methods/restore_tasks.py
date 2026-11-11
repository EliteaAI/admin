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

""" Method: project restore workers

Restores run in a worker process started by this pylon, not in the request:
under gevent the web worker is one OS thread, and parsing a large backup
there stalls every other request of the instance.
"""

from tools import context, log, web  # pylint: disable=E0611,E0401
from tools import config as c  # pylint: disable=E0401

from ..utils import restore_jobs
from ..utils import restore_runner


DEFAULT_MAX_ARCHIVE_MB = 4096
DEFAULT_TASK_LIMIT = 1
DEFAULT_LOCK_TIMEOUT = "30s"
DEFAULT_STALE_AFTER_SECONDS = 600
RETENTION_DAYS = 7
SPOOL_MAX_AGE_SECONDS = 86400


class Method:  # pylint: disable=E1101,R0903
    """ Method Resource """

    @web.init()
    def _restore_tasks_init(self):
        config = self.descriptor.config
        try:
            max_archive_mb = int(config.get("backup_max_archive_mb", DEFAULT_MAX_ARCHIVE_MB))
        except (TypeError, ValueError):
            max_archive_mb = DEFAULT_MAX_ARCHIVE_MB
        #
        self.restore_settings = {
            "max_archive_bytes": max_archive_mb * 1024 * 1024,
            "lock_timeout": config.get("restore_lock_timeout", DEFAULT_LOCK_TIMEOUT),
            "stale_after": int(config.get("restore_stale_after", DEFAULT_STALE_AFTER_SECONDS)),
            "spool_dir": restore_runner.spool_dir(config),
        }
        self.restore_job_schema = c.POSTGRES_SCHEMA
        #
        connection = context.db.engine.raw_connection()
        try:
            restore_jobs.ensure_table(connection, self.restore_job_schema)
        finally:
            connection.close()
        #
        # Jobs this instance was running before a restart can not finish. A
        # worker that survived it (it exits within seconds of losing its pylon,
        # but may not have yet) is stopped first: failing the job frees the
        # project, and the old worker must not restore it alongside a retry.
        store = self.restore_job_store()
        for job in store.instance_jobs(context.node_name):
            if job["task_id"] and restore_runner.worker_alive(job["task_id"]):
                log.warning("project_restore: stopping the leftover worker of job %s", job["id"])
                restore_runner.kill_worker(int(job["task_id"]))
        failed = store.fail_instance_jobs(context.node_name)
        if failed:
            log.warning("project_restore: marked %s interrupted restore job(s) failed", failed)
        #
        self.restore_workers = restore_runner.Workers(
            int(config.get("restore_task_limit", DEFAULT_TASK_LIMIT)),
        )

    @web.deinit()
    def _restore_tasks_deinit(self):
        # A worker can not finish without this pylon: its job is failed on the next boot
        self.restore_workers.stop_all()

    @web.method()
    def restore_worker_database(self):
        """ Connection settings handed to a restore worker """
        return {
            "host": c.POSTGRES_HOST, "port": c.POSTGRES_PORT, "user": c.POSTGRES_USER,
            "password": c.POSTGRES_PASSWORD, "database": c.POSTGRES_DB,
        }

    @web.method()
    def restore_job_store(self):
        """ Job store over pooled connections, for the web process """
        return restore_jobs.JobStore(
            context.db.engine.raw_connection, self.restore_job_schema,
            release=lambda connection: connection.close(),
        )

    @web.method()
    def restore_jobs_reap(self):
        summary = self.restore_job_store().reap(self.restore_settings["stale_after"], RETENTION_DAYS)
        summary["spools"] = restore_runner.remove_stale_spools(
            self.restore_settings["spool_dir"], SPOOL_MAX_AGE_SECONDS,
        )
        if summary["failed"] or summary["deleted"] or summary["spools"]:
            log.info("project_restore: reaped %s", summary)
        return summary
