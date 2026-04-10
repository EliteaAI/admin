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

""" Task """

import io
import time

from tools import context  # pylint: disable=E0401

from .logs import make_logger


def create_database(*args, **kwargs):
    """Create a new PostgreSQL database. Param: database name."""
    #
    with make_logger() as log:
        log.info("Starting")
        start_ts = time.time()
        #
        try:
            if "param" not in kwargs:
                raise ValueError("Param is not set")
            #
            target_db = kwargs["param"].strip()
            #
            from tools import config  # pylint: disable=C0415,E0401
            #
            if config.DATABASE_VENDOR != "postgres":
                log.error("DB vendor is not supported: %s", config.DATABASE_VENDOR)
            #
            target_db_url = 'postgresql://{username}:{password}@{host}:{port}/{database}'.format(  # pylint: disable=C0209
                host=config.POSTGRES_HOST,
                port=config.POSTGRES_PORT,
                username=config.POSTGRES_USER,
                password=config.POSTGRES_PASSWORD,
                database=target_db
            )
            #
            log.info("Target DB: %s", target_db_url)
            #
            import sqlalchemy  # pylint: disable=C0415,E0401
            #
            core_db_url = context.db.url
            core_engine = sqlalchemy.create_engine(
                core_db_url,
                isolation_level="AUTOCOMMIT",
            )
            #
            with core_engine.connect() as connection:
                connection.execute(
                    sqlalchemy.text(f"CREATE DATABASE {target_db}")
                )
        except:  # pylint: disable=W0702
            log.exception("Got exception, stopping")
        #
        end_ts = time.time()
        log.info("Exiting (duration = %s)", end_ts - start_ts)


def create_tables(*args, **kwargs):
    """Apply DB schema migrations for shared tables and all successful projects. No params."""
    #
    with make_logger() as log:
        log.info("Starting")
        start_ts = time.time()
        #
        try:
            from tools import db  # pylint: disable=C0415,E0401
            #
            log.info("Getting shared metadata")
            shared_metadata = db.get_shared_metadata()
            #
            log.info("Applying shared metadata")
            with db.get_session(None) as shared_db:
                shared_metadata.create_all(bind=shared_db.connection())
                shared_db.commit()
            #
            log.info("Getting project metadata")
            tenant_metadata = db.get_tenant_specific_metadata()
            #
            log.info("Getting project list")
            project_list = context.rpc_manager.timeout(120).project_list(
                filter_={"create_success": True},
            )
            #
            for project in project_list:
                log.info("Applying project metadata: %s", project)
                with db.get_session(project["id"]) as tenant_db:
                    tenant_metadata.create_all(bind=tenant_db.connection())
                    tenant_db.commit()
        except:  # pylint: disable=W0702
            log.exception("Got exception, stopping")
        #
        end_ts = time.time()
        log.info("Exiting (duration = %s)", end_ts - start_ts)


def create_tables_for_failed(*args, **kwargs):
    """Apply DB schema migrations only for projects with create_success=False. No params."""
    #
    with make_logger() as log:
        log.info("Starting")
        start_ts = time.time()
        #
        try:
            from tools import db  # pylint: disable=C0415,E0401
            #
            log.info("Getting project metadata")
            tenant_metadata = db.get_tenant_specific_metadata()
            #
            log.info("Getting failed project list")
            project_list = context.rpc_manager.timeout(120).project_list(
                filter_={"create_success": False},
            )
            #
            for project in project_list:
                log.info("Applying failed project metadata: %s", project)
                with db.get_session(project["id"]) as tenant_db:
                    tenant_metadata.create_all(bind=tenant_db.connection())
                    tenant_db.commit()
        except:  # pylint: disable=W0702
            log.exception("Got exception, stopping")
        #
        end_ts = time.time()
        log.info("Exiting (duration = %s)", end_ts - start_ts)


def propose_migrations(*args, **kwargs):  # pylint: disable=R0914
    """Compare current DB schema against models and output SQL migration statements. No params."""
    #
    with make_logger() as log:
        log.info("Starting")
        start_ts = time.time()
        #
        try:
            from tools import db  # pylint: disable=C0415,E0401
            from tools import config as c  # pylint: disable=C0415,E0401
            #
            from sqlalchemy import MetaData  # pylint: disable=C0415,E0401
            #
            from alembic.migration import MigrationContext  # pylint: disable=C0415,E0401
            from alembic.autogenerate import compare_metadata, produce_migrations  # pylint: disable=C0415,E0401
            from alembic.operations import Operations  # pylint: disable=C0415,E0401
            #
            # ---
            #
            log.info("Getting shared metadata")
            shared_metadata = db.get_shared_metadata()
            #
            log.info("Comparing shared metadata")
            with db.get_session(None) as shared_db:
                def _non_auth_name(name, type_, parent_names):  # pylint: disable=W0613
                    if name is not None:
                        return "auth_core" not in name
                    #
                    return True
                #
                migration_ctx = MigrationContext.configure(
                    connection=shared_db.connection(),
                    opts={
                        "include_name": _non_auth_name,
                    },
                )
                #
                db_diffs = compare_metadata(migration_ctx, shared_metadata)
                #
                for db_diff in db_diffs:
                    log.info("- Shared DB diff: %s", db_diff)
                #
                db_script = produce_migrations(migration_ctx, shared_metadata)
                #
                output_buffer = io.StringIO()
                #
                sql_migration_context = MigrationContext.configure(
                    connection=migration_ctx.connection,
                    opts={
                        "as_sql": True,
                        "output_buffer": output_buffer,
                    },
                )
                operations = Operations(sql_migration_context)
                #
                to_process = [db_script.upgrade_ops]
                #
                while to_process:
                    current_op = to_process.pop(0)
                    #
                    if hasattr(current_op, "ops"):
                        to_process.extend(current_op.ops)
                        continue
                    #
                    operations.invoke(current_op)
                #
                sql_lines = "\n".join([
                    line.strip()
                    for line in output_buffer.getvalue().splitlines()
                    if line.strip()
                ])
                #
                log.info("- - Shared DB SQLs:\n---\n%s\n---", sql_lines)
            #
            # ---
            #
            def _get_tenant_specific_metadata(target_schema):
                meta = MetaData(schema=target_schema)
                for table in db.Base.metadata.tables.values():
                    if table.schema == c.POSTGRES_TENANT_SCHEMA:
                        table.tometadata(meta, schema=target_schema)
                return meta
            #
            log.info("Getting project list")
            project_list = context.rpc_manager.timeout(120).project_list(
                filter_={"create_success": True},
            )
            #
            if project_list:
                project = project_list[0]
                #
                log.info("Processing project: %s", project)
                with db.get_session(project["id"]) as tenant_db:
                    from tools import project_constants as pc  # pylint: disable=E0401,C0415
                    project_schema = pc["PROJECT_SCHEMA_TEMPLATE"].format(project["id"])
                    #
                    log.info("Getting project metadata")
                    tenant_metadata = _get_tenant_specific_metadata(project_schema)
                    #
                    # Shoud fix key -> table relation after such changes
                    # for table in tenant_metadata.sorted_tables:
                    #     table.schema = project_schema
                    #
                    def _project_schema_name(name, type_, parent_names):  # pylint: disable=W0613
                        if type_ == "schema":
                            return name == project_schema
                        #
                        return True
                    #
                    migration_ctx = MigrationContext.configure(
                        connection=tenant_db.connection(),
                        opts={
                            "include_schemas": True,
                            "include_name": _project_schema_name,
                        },
                    )
                    #
                    log.info("Comparing project metadata")
                    db_diffs = compare_metadata(migration_ctx, tenant_metadata)
                    #
                    for db_diff in db_diffs:
                        log.info("- Project DB diff: %s", db_diff)
                    #
                    db_script = produce_migrations(migration_ctx, tenant_metadata)
                    #
                    output_buffer = io.StringIO()
                    #
                    sql_migration_context = MigrationContext.configure(
                        connection=migration_ctx.connection,
                        opts={
                            "as_sql": True,
                            "output_buffer": output_buffer,
                        },
                    )
                    operations = Operations(sql_migration_context)
                    #
                    to_process = [db_script.upgrade_ops]
                    #
                    while to_process:
                        current_op = to_process.pop(0)
                        #
                        if hasattr(current_op, "ops"):
                            to_process.extend(current_op.ops)
                            continue
                        #
                        operations.invoke(current_op)
                    #
                    sql_lines = "\n".join([
                        line.strip()
                        for line in output_buffer.getvalue().splitlines()
                        if line.strip()
                    ])
                    #
                    log.info("- - Project DB SQLs:\n---\n%s\n---", sql_lines)
            #
        except:  # pylint: disable=W0702
            log.exception("Got exception, stopping")
        #
        end_ts = time.time()
        log.info("Exiting (duration = %s)", end_ts - start_ts)
