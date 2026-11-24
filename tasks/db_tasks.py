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
import json
import time

from sqlalchemy.exc import NoReferencedTableError  # pylint: disable=E0401

from plugins.admin.utils import schema_tables  # pylint: disable=E0401

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


CREATE_TABLES_PARAMS = {"dry_run", "project_id"}
ALL_PROJECTS = "all"


def _reject_duplicate_keys(pairs):
    """ Build the param dict from key/value pairs, refusing a repeated key """
    parsed = {}
    for key, value in pairs:
        if key in parsed:
            raise ValueError(f"Duplicate param '{key}'")
        parsed[key] = value
    return parsed


def _parse_create_tables_param(param):
    """ create_tables param: a JSON object or 'key=value;key=value'; a malformed fragment or repeated key is refused """
    param = (param or "").strip()
    if not param:
        return {}
    if param.startswith("{"):
        try:
            return json.loads(param, object_pairs_hook=_reject_duplicate_keys)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in param: {exc}") from exc
    pairs = []
    for fragment in param.split(";"):
        fragment = fragment.strip()
        if not fragment:
            continue
        if "=" not in fragment:
            raise ValueError(f"Malformed param fragment '{fragment}'; expected key=value")
        key, _, value = fragment.partition("=")
        pairs.append((key.strip(), value.strip()))
    return _reject_duplicate_keys(pairs)


def _parse_dry_run(params):
    """ dry_run of create_tables: absent means true, only an explicit true/false is accepted """
    if "dry_run" not in params:
        return True
    value = params["dry_run"]
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    raise ValueError(f"Invalid dry_run value {value!r}; expected true or false")


def _parse_project_id(params):
    """ project_id of create_tables: absent means all, otherwise 'all' or a positive integer """
    if "project_id" not in params:
        return ALL_PROJECTS
    value = params["project_id"]
    if isinstance(value, str):
        text = value.strip()
        if text.lower() == ALL_PROJECTS:
            return ALL_PROJECTS
        if text.isascii() and text.isdigit() and int(text) > 0:
            return int(text)
    elif isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    raise ValueError(
        f"Invalid project_id value {value!r}; expected a positive integer project id or 'all'"
    )


def _fetch_provisioned_project(project_id):
    """ The single project a scoped run targets; refuses a missing or unprovisioned one """
    project = context.rpc_manager.timeout(120).project_list(project_id=project_id)
    if project is None:
        raise ValueError(f"Project {project_id} not found")
    if project.get("create_success") is not True:
        raise ValueError(
            f"Project {project_id} was not provisioned successfully; use create_tables_for_failed"
        )
    return project


def _format_table_names(tables):
    return "[" + ", ".join(table.name for table in tables) + "]"


def _format_outside_objects(outside):
    return ", ".join(f"{kind} {name} (\u2192 {schema})" for kind, name, schema in outside)


def _process_shared_schema(log, db, dry_run, is_shared_apply_allowed):
    """ Report the missing shared tables, creating them only in an all-projects apply """
    with db.get_session() as shared_db:
        connection = shared_db.connection()
        shared_metadata = db.get_shared_metadata()
        planned = schema_tables.plan_missing_tables(connection, shared_metadata)
        names = ", ".join(table.name for table in planned)
        if not planned:
            log.info("shared: up to date")
            return len(planned), 0
        if not is_shared_apply_allowed:
            log.info(
                "shared: not applied in single-project mode (%s pending: %s); run with project_id=all",
                len(planned), names,
            )
            return len(planned), 0
        if dry_run:
            log.info("shared: would create [%s]", names)
            return len(planned), 0
        shared_metadata.create_all(bind=connection, tables=planned)
        shared_db.commit()
        log.info("shared: created [%s]", names)
        return len(planned), len(planned)


def _process_project_schema(log, db, project_id, tenant_metadata, dry_run, is_single_project):  # pylint: disable=R0913,R0917
    """ Plan one project's missing tables and create them unless dry run; returns the outcome name """
    with db.get_session(project_id) as tenant_db:
        connection = tenant_db.connection()
        planned = schema_tables.plan_missing_tables(connection, tenant_metadata)
        if not planned:
            return "up_to_date"
        outside = schema_tables.find_ddl_outside_schema(
            connection, tenant_metadata, planned,
            db.schema_mapper(project_id),
        )
        if outside and is_single_project:
            log.error(
                "project %s: needs a shared-schema change first: %s; run with project_id=all; "
                "not created: %s",
                project_id, _format_outside_objects(outside), _format_table_names(planned),
            )
            return "stopped"
        if dry_run:
            log.info("project %s: would create %s", project_id, _format_table_names(planned))
            if outside:
                log.info("project %s: would also create %s", project_id, _format_outside_objects(outside))
            return "planned"
        tenant_metadata.create_all(bind=connection, tables=planned)
        tenant_db.commit()
        log.info("project %s: created %s", project_id, _format_table_names(planned))
        if outside:
            log.info("project %s: also created %s", project_id, _format_outside_objects(outside))
        return "applied"


def _try_process_project_schema(log, db, project_id, tenant_metadata, dry_run, is_single_project):  # pylint: disable=R0913,R0917
    """ One project's pass, with its failure logged so the other projects still run """
    try:
        return _process_project_schema(log, db, project_id, tenant_metadata, dry_run, is_single_project)
    except NoReferencedTableError as exc:
        log.error("project %s: failed: model defect: %s", project_id, exc)
    except Exception as exc:  # pylint: disable=W0703
        log.error("project %s: failed: %s: %s", project_id, type(exc).__name__, exc)
    return "failed"


def create_tables(*args, **kwargs):  # pylint: disable=R0914,R0915
    """Preview or apply database schema migrations for one project or all eligible projects. Dry run is enabled by default. Review the results before setting dry_run=false. Shared-table migrations are included only when targeting all projects. Param: 'project_id=<id>|all;dry_run=true|false' or the same as JSON; both optional (defaults all, true)."""
    #
    with make_logger() as log:
        log.info("Starting")
        start_ts = time.time()
        #
        try:
            from tools import db  # pylint: disable=C0415,E0401
            #
            params = _parse_create_tables_param(kwargs.get("param"))
            unknown_params = set(params) - CREATE_TABLES_PARAMS
            if unknown_params:
                raise ValueError(
                    f"Unknown param(s): {sorted(unknown_params)}; allowed: {sorted(CREATE_TABLES_PARAMS)}"
                )
            dry_run = _parse_dry_run(params)
            requested_project = _parse_project_id(params)
            is_single_project = requested_project != ALL_PROJECTS
            #
            if is_single_project:
                project_ids = [_fetch_provisioned_project(requested_project)["id"]]
                scope = f"project {project_ids[0]}"
            else:
                project_ids = [
                    project["id"]
                    for project in context.rpc_manager.timeout(120).project_list(
                        filter_={"create_success": True},
                    )
                ]
                scope = f"all ({len(project_ids)} eligible projects)"
            #
            log.info(
                "create_tables: scope=%s; mode=%s; requested_by=%s",
                scope, "DRY RUN" if dry_run else "APPLY", kwargs.get("_executing_user_id"),
            )
            if "dry_run" not in params:
                log.warning("dry_run not given: previewing only, nothing will be written; pass dry_run=false to apply")
            #
            outcomes = {
                name: [] for name in ("planned", "applied", "up_to_date", "skipped", "stopped", "failed")
            }
            shared_planned, shared_applied = 0, 0
            has_shared_pass_failed = False
            try:
                shared_planned, shared_applied = _process_shared_schema(
                    log, db, dry_run, is_shared_apply_allowed=not is_single_project,
                )
            except Exception as exc:  # pylint: disable=W0703
                if is_single_project:
                    raise
                has_shared_pass_failed = True
                log.error("shared: failed: %s: %s", type(exc).__name__, exc)
                log.error("projects: %s skipped (shared pass failed)", len(project_ids))
                outcomes["skipped"] = list(project_ids)
            #
            if not has_shared_pass_failed:
                tenant_metadata = db.get_tenant_specific_metadata()
                for project_id in project_ids:
                    outcome = _try_process_project_schema(
                        log, db, project_id, tenant_metadata, dry_run, is_single_project,
                    )
                    outcomes[outcome].append(project_id)
            #
            log.info(
                "Done: projects planned=%s applied=%s up_to_date=%s skipped=%s stopped=%s failed=%s; "
                "shared planned=%s applied=%s",
                len(outcomes["planned"]) + len(outcomes["applied"]), len(outcomes["applied"]),
                len(outcomes["up_to_date"]), len(outcomes["skipped"]),
                len(outcomes["stopped"]), len(outcomes["failed"]),
                shared_planned, shared_applied,
            )
            if dry_run:
                log.info("Dry run: nothing written; re-run with dry_run=false to apply")
            #
            problems = [
                f"{len(outcomes[outcome])} project(s) {wording}: {outcomes[outcome]}"
                for outcome, wording in (
                    ("failed", "failed"),
                    ("stopped", "need a shared-schema change first"),
                )
                if outcomes[outcome]
            ]
            if has_shared_pass_failed:
                problems = ["shared pass failed; no project was processed"]
        except:  # pylint: disable=W0702
            log.exception("Got exception, stopping task")
            raise
        finally:
            log.info("Exiting (duration = %s)", time.time() - start_ts)
        #
        if problems:
            raise RuntimeError("create_tables: " + "; ".join(problems))


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


def lifecycle_audit_provision(*args, **kwargs):
    """Create the lifecycle audit tables, indexes, triggers and partitions (#7504). Idempotent. No params."""
    #
    with make_logger() as log:
        log.info("Starting")
        start_ts = time.time()
        #
        try:
            from tools import this  # pylint: disable=C0415,E0401
            #
            created = this.for_module("admin").module.lifecycle_audit_provision(task_log=log)
            log.info("Partitions ensured: %s", created)
        except:  # pylint: disable=W0702
            log.exception("Got exception, stopping")
        #
        end_ts = time.time()
        log.info("Exiting (duration = %s)", end_ts - start_ts)
