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

""" Lifecycle audit (#7504): provisioning, writer, drainer, partitions and retention """

import contextlib
import threading
import time

import flask  # pylint: disable=E0401

from tools import context, log, web  # pylint: disable=E0611,E0401
from tools import config as c  # pylint: disable=E0401

from ..utils import lifecycle_audit as la

DEFAULTS = {
    "enabled": True,
    # None finds auth_core's inbox by name (its schema follows pylon_auth's search_path)
    "auth_schema": None,
    "drain_interval_seconds": 2,
    "drain_batch_size": 500,
    "partition_ahead_months": 2,
    # None keeps every month; N drops whole months older than N
    "retention_months": None,
    "retention_keep_detached": False,
}

REPAIR_INTERVAL_SECONDS = 60


@contextlib.contextmanager
def _raw_connection():
    connection = context.db.engine.raw_connection()
    try:
        yield connection
    finally:
        connection.close()


def _dbapi_connection(session):
    """ The psycopg2 connection under a SQLAlchemy session's current transaction """
    return session.connection().connection.dbapi_connection


class Method:  # pylint: disable=E1101,R0903
    """ Method Resource """

    @web.init()
    def _lifecycle_audit_init(self):
        self.lifecycle_audit_config = dict(DEFAULTS, **(self.descriptor.config.get("lifecycle_audit") or {}))
        self.lifecycle_audit_stop = threading.Event()
        self.lifecycle_audit_thread = None
        self.lifecycle_audit_last_repair = 0.0
        if not self.lifecycle_audit_config["enabled"]:
            return
        try:
            self.lifecycle_audit_ensure_partitions()
        except Exception:  # pylint: disable=W0703
            log.exception("Lifecycle audit: provisioning failed; events wait in their inboxes")
        #
        self.lifecycle_audit_thread = threading.Thread(
            target=self._lifecycle_audit_drain_loop, name="lifecycle-audit-drainer", daemon=True,
        )
        self.lifecycle_audit_thread.start()

    @web.deinit()
    def _lifecycle_audit_deinit(self):
        self.lifecycle_audit_stop.set()
        if self.lifecycle_audit_thread is not None:
            self.lifecycle_audit_thread.join(timeout=10)

    #
    # Writer
    #

    @web.method()
    def lifecycle_audit_record(self, session, events):
        """ Add events to the admin inbox on the caller's SQLAlchemy session; committed with it

        Never raises: an audit outage must not block the change (AC-23).
        """
        if not self.lifecycle_audit_config["enabled"]:
            return
        events = events if isinstance(events, list) else [events]
        try:
            recorded = la.store.record(_dbapi_connection(session), c.POSTGRES_SCHEMA, events)
        except Exception:  # pylint: disable=W0703
            log.exception("Lifecycle audit write failed; applying the change without its audit event")
            return
        if not recorded:
            log.error("Lifecycle audit write failed; applying the change without its audit event")

    @web.method()
    def lifecycle_audit_ctx(self, executing_user_id=None):
        """ Actor context of the current request, or of an admin task when executing_user_id is given """
        if executing_user_id is not None:
            return la.events.ctx_for_task(executing_user_id, self._lifecycle_audit_user(executing_user_id))
        if not flask.has_request_context():
            return dict(la.events.SYSTEM_CTX)
        auth = getattr(flask.g, "auth", None)
        request_id = flask.request.headers.get("X-Request-Id")
        auth_id = getattr(auth, "id", None)
        user = self._lifecycle_audit_user(auth_id) if getattr(auth, "type", None) in ("user", "token") else None
        return la.events.ctx_from_auth(auth, user=user, request_id=request_id)

    @web.method()
    def lifecycle_audit_scim_ctx(self):
        """ Actor context of SCIM provisioning / group sync """
        return dict(la.events.SCIM_CTX)

    @web.method()
    def _lifecycle_audit_user(self, user_id):
        if not isinstance(user_id, int):
            return None
        try:
            return self.context.rpc_manager.timeout(5).auth_get_user(user_id=user_id)
        except Exception:  # pylint: disable=W0703
            return None

    #
    # Maintenance
    #

    # @web.rpc handlers are not module attributes in pylon: each RPC wraps a @web.method doing the work

    @web.rpc("admin_lifecycle_audit_ensure_partitions")
    def _lifecycle_audit_ensure_partitions_rpc(self, **kwargs):
        _ = kwargs
        return self.lifecycle_audit_ensure_partitions()

    @web.method()
    def lifecycle_audit_ensure_partitions(self):
        """ Tables, triggers and the current + lookahead months (daily cron, ready, self-heal) """
        with _raw_connection() as connection:
            created = la.store.ensure_schema(
                connection, c.POSTGRES_SCHEMA,
                ahead_months=self.lifecycle_audit_config["partition_ahead_months"],
            )
        return created

    @web.rpc("admin_lifecycle_audit_apply_retention")
    def _lifecycle_audit_apply_retention_rpc(self, **kwargs):
        _ = kwargs
        return self.lifecycle_audit_apply_retention()

    @web.method()
    def lifecycle_audit_apply_retention(self):
        """ Drop (or detach) whole months past retention_months; nothing when it is None """
        config = self.lifecycle_audit_config
        with _raw_connection() as connection:
            expired = la.store.apply_retention(
                connection, c.POSTGRES_SCHEMA, config["retention_months"],
                keep_detached=config["retention_keep_detached"],
            )
        if expired:
            log.info("Lifecycle audit retention: %s %s", "detached" if config["retention_keep_detached"] else "dropped", expired)
        return expired

    @web.rpc("admin_lifecycle_audit_drain")
    def _lifecycle_audit_drain_rpc(self, **kwargs):
        _ = kwargs
        return self.lifecycle_audit_drain()

    @web.method()
    def lifecycle_audit_drain(self):
        """ One drain pass; months with no partition are created (rate-limited) and drained next pass """
        config = self.lifecycle_audit_config
        missing = set()
        with _raw_connection() as connection:
            moved = la.store.drain(
                connection, c.POSTGRES_SCHEMA, config["auth_schema"],
                batch_size=config["drain_batch_size"], missing=missing,
            )
            if missing and time.monotonic() - self.lifecycle_audit_last_repair > REPAIR_INTERVAL_SECONDS:
                self.lifecycle_audit_last_repair = time.monotonic()
                log.error("Lifecycle audit: events wait for missing partitions %s; creating them", sorted(missing))
                for month in sorted(missing):
                    la.store.ensure_partitions(connection, c.POSTGRES_SCHEMA, month, month)
        return moved

    @web.method()
    def _lifecycle_audit_drain_loop(self):
        interval = float(self.lifecycle_audit_config["drain_interval_seconds"])
        while not self.lifecycle_audit_stop.wait(interval):
            try:
                self.lifecycle_audit_drain()
            except Exception:  # pylint: disable=W0703
                log.exception("Lifecycle audit drain failed; retrying")

    @web.method()
    def lifecycle_audit_register_schedules(self):
        """ Daily partition lookahead, monthly retention """
        for name, cron, rpc_func in (
                ("lifecycle_audit_ensure_partitions", "17 3 * * *", "admin_lifecycle_audit_ensure_partitions"),
                ("lifecycle_audit_apply_retention", "43 3 1 * *", "admin_lifecycle_audit_apply_retention"),
        ):
            try:
                self.context.rpc_manager.timeout(5).scheduling_create_if_not_exists({
                    "name": name, "cron": cron, "rpc_func": rpc_func, "rpc_kwargs": {}, "active": True,
                })
            except Exception:  # pylint: disable=W0703
                log.warning("Could not register the %s schedule", name, exc_info=True)

    #
    # Reads
    #

    @web.method()
    def lifecycle_audit_query(self, params):
        """ One page of events; params validated by utils.lifecycle_audit.query.parse """
        with _raw_connection() as connection:
            return la.store.query(connection, c.POSTGRES_SCHEMA, params)

    @web.method()
    def lifecycle_audit_export(self, params):
        """ CSV chunks of every matching row; the connection lives as long as the stream """
        with _raw_connection() as connection:
            yield from la.store.export_csv(connection, c.POSTGRES_SCHEMA, params)
