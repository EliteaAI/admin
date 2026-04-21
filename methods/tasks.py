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

""" Method """

import time
import functools

import arbiter

from centry_logging.handlers.eventnode import EventNodeLogHandler  # pylint: disable=E0611,E0401

from tools import context, log, web  # pylint: disable=E0611,E0401

from ..tasks import db_tasks
from ..tasks import indexer_tasks
from ..tasks import project_tasks
from ..tasks import mesh_tasks
from ..tasks import role_migration


class Method:  # pylint: disable=E1101,R0903
    """
        Method Resource

        self is pointing to current Module instance

        web.method decorator takes zero or one argument: method name
        Note: web.method decorator must be the last decorator (at top)

    """

    @web.init()
    def _tasks_init(self):
        self.admin_tasks = {}  # name -> func
        #
        self.event_node = arbiter.make_event_node(
            config={
                "type": "MockEventNode",
            },
        )
        #
        self.task_node = arbiter.TaskNode(
            self.event_node,
            pool="admin",
            task_limit=None,
            ident_prefix="admin_",
            multiprocessing_context="threading",
            task_retention_period=3600,
            housekeeping_interval=60,
            thread_scan_interval=0.1,
            start_max_wait=3,
            query_wait=3,
            watcher_max_wait=3,
            stop_node_task_wait=3,
            result_max_wait=3,
            result_transport="memory",
            start_attempts=1,
        )
        #
        self.task_node.start()
        #
        local_admin_tasks = [
            ("create_tables", db_tasks.create_tables),
            ("create_tables_for_failed", db_tasks.create_tables_for_failed),
            ("propose_migrations", db_tasks.propose_migrations),
            ("create_database", db_tasks.create_database),
            #
            ("indexer_migrate", indexer_tasks.indexer_migrate),
            #
            ("list_failed_projects", project_tasks.list_failed_projects),
            ("delete_failed_projects", project_tasks.delete_failed_projects),
            ("fix_personal_projects", project_tasks.fix_personal_projects),
            ("sync_pgvector_credentials", project_tasks.sync_pgvector_credentials),
            ("recreate_project_tokens", project_tasks.recreate_project_tokens),
            ("delete_ghost_users", project_tasks.delete_ghost_users),
            #
            ("mesh_get_plugin_frozen_requirements", mesh_tasks.mesh_get_plugin_frozen_requirements),
            #
            ("migrate_admin_to_super_admin", role_migration.migrate_admin_to_super_admin),
        ]
        #
        for task_name, task_func in local_admin_tasks:
            self.register_admin_task(task_name, task_func)

    @web.method()
    def register_admin_task(self, name, func):
        """ Method """
        if name in self.admin_tasks:
            raise RuntimeError(f"Task already registered: {name}")
        #
        partial_func = functools.partial(self.execute_admin_task, func)
        #
        self.admin_tasks[name] = partial_func
        self.task_node.register_task(partial_func, name)

    @web.method()
    def unregister_admin_task(self, name, func):
        """ Method """
        _ = func
        #
        if name not in self.admin_tasks:
            raise RuntimeError(f"Task is not registered: {name}")
        #
        partial_func = self.admin_tasks.pop(name)
        #
        self.task_node.unregister_task(partial_func, name)

    @staticmethod
    def _get_tracer():
        """ Get OpenTelemetry tracer if tracing is enabled """
        #
        # NOTE: tracing calls (this.for_module, get_tracer) deadlock in task
        # threads due to gevent cooperative scheduling and internal locks.
        # Disabled for now; admin task auditing will use a different approach.
        #
        return None

    @web.method()
    def execute_admin_task(self, func, *args, **kwargs):
        """ Method """
        #
        # Extract audit context (injected by API handler)
        #
        user_id = kwargs.pop("_user_id", None)
        #
        handler = None
        task_id = None
        task_name = "unknown"
        #
        try:
            event_node_config = context.module_manager.descriptors[
                "logging_hub"
            ].module.event_node_config
            #
            import tasknode_task  # pylint: disable=E0401,C0415
            #
            task_id = tasknode_task.id
            task_name = getattr(tasknode_task, 'name', 'unknown')
            #
            handler = EventNodeLogHandler({
                "event_node": event_node_config,
                "labels": {
                    "tasknode_task": f"id:{tasknode_task.id}",
                    "stream_id": "",  # until datasources are updated or removed
                }
            })
            #
            log.prepare_handler(handler)
            log.state.local.handler = handler
        except:  # pylint: disable=W0702
            log.exception("Got exception, using default logs only")
        #
        log.info("Starting")
        start_ts = time.time()
        #
        try:
            return func(*args, **kwargs)
        except:  # pylint: disable=W0702
            log.exception("Got exception, stopping")
            raise
        #
        finally:
            end_ts = time.time()
            log.info("Exiting (duration = %s)", end_ts - start_ts)
            #
            if handler is not None:
                # Allow time for the EventNode to flush buffered log
                # messages through Redis before closing the connection
                time.sleep(0.5)
                delattr(log.state.local, "handler")
                handler.close()

    def _execute_traced(self, tracer, func, args, kwargs,
                        task_name, task_id, user_id, start_ts):
        """ Execute task function with OTEL tracing span """
        from opentelemetry.trace import SpanKind, Status, StatusCode  # pylint: disable=C0415
        #
        attributes = {
            'telemetry.data_type': 'admin_task_execution',
            'task.name': task_name or 'unknown',
            'task.id': task_id or '',
        }
        if user_id is not None:
            attributes['user.id'] = user_id
        #
        with tracer.start_as_current_span(
            f"Admin Task: {task_name}",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            try:
                result = func(*args, **kwargs)
                duration_ms = (time.time() - start_ts) * 1000
                span.set_attribute('task.duration_ms', duration_ms)
                span.set_status(Status(StatusCode.OK))
                return result
            except Exception as exc:
                duration_ms = (time.time() - start_ts) * 1000
                span.set_attribute('task.duration_ms', duration_ms)
                span.set_status(Status(StatusCode.ERROR, str(exc)))
                raise

    @web.method()
    def present_admin_tasks(self):
        """ Method """
        result = list(self.admin_tasks)
        result.sort()
        return result

    @web.method()
    def present_admin_tasks_with_descriptions(self):
        """ Return task names with descriptions extracted from docstrings """
        result = []
        for name in sorted(self.admin_tasks):
            description = ""
            try:
                partial_func = self.admin_tasks[name]
                func = partial_func.args[0] if partial_func.args else None
                #
                # Unwrap partials and decorators to find the original function
                #
                for _ in range(10):  # safety limit
                    if isinstance(func, functools.partial):
                        func = func.func if not func.args else func.args[0]
                    elif hasattr(func, '__wrapped__'):
                        func = func.__wrapped__
                    elif hasattr(func, '__func__'):
                        func = func.__func__
                    else:
                        break
                #
                if func and hasattr(func, '__doc__') and func.__doc__:
                    doc = func.__doc__.strip()
                    # Filter out useless docstrings
                    first_line = doc.split("\n")[0].strip()
                    skip = {
                        "task", "method", "",
                        "pylon module", "task module",
                        "module", "resource",
                        "method resource",
                    }
                    if first_line.lower() not in skip \
                            and not first_line.startswith("partial("):
                        description = first_line
            except Exception:  # pylint: disable=W0703
                pass
            result.append({"name": name, "description": description})
        return result

    @web.deinit()
    def _tasks_deinit(self):
        for task_name, task_func in list(self.admin_tasks.items()):
            self.unregister_admin_task(task_name, task_func)
        #
        self.task_node.stop()
