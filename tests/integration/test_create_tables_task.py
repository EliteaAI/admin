"""Integration tests for the create_tables admin task and utils/schema_tables.py (issue #7548).

Validation tests run everywhere. The planner, scope guard and apply tests need
a real PostgreSQL: a throwaway database is created next to the one in
ELITEA_TEST_PG_DSN and dropped afterwards.

    ELITEA_TEST_PG_DSN="postgresql://centry:changeme@localhost:5432/db" \\
        python tests/run_tests.py integration/test_create_tables_task.py

The PostgreSQL tests are skipped when the variable is not set.
"""
import contextlib
import importlib
import importlib.util
import os
import sys
import types
import uuid

import pytest
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Session

PACKAGE = "admin_db_tasks_under_test"
DSN = os.environ.get("ELITEA_TEST_PG_DSN")
needs_postgres = pytest.mark.skipif(not DSN, reason="ELITEA_TEST_PG_DSN is not set")

TENANT = "tenant"
SHARED = "shared_s"


class RecordingLog:
    """Captures formatted messages the way the operator would read them."""

    def __init__(self):
        self.lines = []

    def _record(self, message, *args):
        self.lines.append(message % args if args else message)

    info = warning = error = exception = debug = critical = _record

    @property
    def text(self):
        return "\n".join(self.lines)


class StubMakeLogger:
    instances = []

    def __enter__(self):
        log = RecordingLog()
        StubMakeLogger.instances.append(log)
        return log

    def __exit__(self, *exc_info):
        return False


class FakeRpc:
    """Mimics context.rpc_manager.timeout(n).project_list(...)."""

    def __init__(self, projects):
        self.projects = projects
        self.calls = []

    def timeout(self, _seconds):
        return self

    def project_list(self, **kwargs):
        self.calls.append(kwargs)
        if "project_id" in kwargs:
            return self.projects.get(kwargs["project_id"])
        return [
            project for project in self.projects.values()
            if project["create_success"] is kwargs["filter_"]["create_success"]
        ]


def make_project(project_id, create_success=True):
    return {"id": project_id, "name": f"p{project_id}", "create_success": create_success}


class SpyDb:
    """A tools.db that must never be reached: validation happens before any session."""

    def __init__(self):
        self.sessions = []

    def get_session(self, project_id=None):
        self.sessions.append(project_id)
        raise AssertionError("db.get_session must not be called")

    def get_shared_metadata(self):
        raise AssertionError("db.get_shared_metadata must not be called")

    def get_tenant_specific_metadata(self):
        raise AssertionError("db.get_tenant_specific_metadata must not be called")


class PostgresDb:
    """tools.db over a real engine, translating the tenant schema to p_<N> like pylon does."""

    def __init__(self, engine, shared_metadata, tenant_metadata):
        self.engine = engine
        self.shared_metadata = shared_metadata
        self.tenant_metadata = tenant_metadata
        self.sessions = []

    def get_session(self, project_id=None):
        self.sessions.append(project_id)
        engine = self.engine
        if project_id is not None:
            engine = engine.execution_options(schema_translate_map={TENANT: f"p_{project_id}"})
        return contextlib.closing(Session(engine))

    def get_shared_metadata(self):
        return self.shared_metadata

    def get_tenant_specific_metadata(self):
        return self.tenant_metadata

    @staticmethod
    def schema_mapper(project_id):
        return f"p_{project_id}"


@pytest.fixture(scope="module", name="db_tasks")
def load_db_tasks(plugin_root):
    """Import the real tasks/db_tasks.py with .logs, tools.context and plugins.admin.utils stubbed."""
    import tools  # noqa: F401  (stubbed by run_tests.py)

    spec = importlib.util.spec_from_file_location(
        "plugins.admin.utils.schema_tables", plugin_root / "utils" / "schema_tables.py",
    )
    schema_tables = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(schema_tables)

    utils_package = types.ModuleType("plugins.admin.utils")
    utils_package.schema_tables = schema_tables
    tasks_package = types.ModuleType(PACKAGE)
    tasks_package.__path__ = [str(plugin_root / "tasks")]
    logs_stub = types.ModuleType(f"{PACKAGE}.logs")
    logs_stub.make_logger = StubMakeLogger

    installed = {
        "plugins": types.ModuleType("plugins"),
        "plugins.admin": types.ModuleType("plugins.admin"),
        "plugins.admin.utils": utils_package,
        "plugins.admin.utils.schema_tables": schema_tables,
        PACKAGE: tasks_package,
        f"{PACKAGE}.logs": logs_stub,
    }
    previous_modules = {name: sys.modules.get(name) for name in installed}
    sys.modules.update(installed)

    previous = {name: getattr(tools, name, None) for name in ("context", "log", "db")}
    tools.context = types.SimpleNamespace(rpc_manager=None)
    tools.log = RecordingLog()

    try:
        yield importlib.import_module(f"{PACKAGE}.db_tasks")
    finally:
        for name in (f"{PACKAGE}.db_tasks", f"{PACKAGE}.lifecycle_tasks"):
            sys.modules.pop(name, None)
        for name, module in previous_modules.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module
        for name, value in previous.items():
            setattr(tools, name, value)


@pytest.fixture
def run(db_tasks):
    """Run create_tables against a fake project RPC and db; returns (log, error)."""
    import tools  # noqa: F401

    def _run(param, db, projects=(), user_id=7):
        rpc = FakeRpc({item["id"]: item for item in projects})
        tools.context.rpc_manager = rpc
        tools.db = db
        StubMakeLogger.instances.clear()
        error = None
        try:
            db_tasks.create_tables(param=param, _executing_user_id=user_id)
        except Exception as exc:  # pylint: disable=W0703
            error = exc
        return StubMakeLogger.instances[-1], error, rpc

    return _run


# --- validation: every bad input fails before any project lookup or session ---


@pytest.mark.parametrize("param, message", [
    ('{"project": 1}', "Unknown param(s): ['project']; allowed: ['dry_run', 'project_id']"),
    ("project_id=1;force=true", "Unknown param(s): ['force']"),
    ('{"project_id": true}', "Invalid project_id value True"),
    ('{"project_id": false}', "Invalid project_id value False"),
    ('{"project_id": 0}', "Invalid project_id value 0"),
    ('{"project_id": -1}', "Invalid project_id value -1"),
    ('{"project_id": 1.5}', "Invalid project_id value 1.5"),
    ('{"project_id": "abc"}', "Invalid project_id value 'abc'"),
    ('{"project_id": null}', "Invalid project_id value None"),
    ('{"project_id": ""}', "Invalid project_id value ''"),
    ('{"project_id": "  "}', "Invalid project_id value '  '"),
    ('{"project_id": [1]}', "Invalid project_id value [1]"),
    ("project_id=;dry_run=false", "Invalid project_id value ''"),
    ("project_id=-5", "Invalid project_id value '-5'"),
    ("project_id=1.0", "Invalid project_id value '1.0'"),
    ("project_id=²", "Invalid project_id value '²'"),
    ('{"dry_run": 0}', "Invalid dry_run value 0"),
    ('{"dry_run": 1}', "Invalid dry_run value 1"),
    ('{"dry_run": null}', "Invalid dry_run value None"),
    ('{"dry_run": ""}', "Invalid dry_run value ''"),
    ("dry_run=no", "Invalid dry_run value 'no'"),
    ("dry_run=off", "Invalid dry_run value 'off'"),
    ("dry_run=0", "Invalid dry_run value '0'"),
    ("project_id14002;dry_run=false", "Malformed param fragment 'project_id14002'"),
    ("project_id=14002;dry_run=false;project_id=all", "Duplicate param 'project_id'"),
    ('{"project_id": 14002, "dry_run": false, "project_id": "all"}', "Duplicate param 'project_id'"),
    ("dry_run", "Malformed param fragment 'dry_run'"),
])
def test_invalid_param_fails_before_any_lookup_or_session(run, param, message):
    db = SpyDb()

    log, error, rpc = run(param, db, projects=[make_project(1), make_project(14002)])

    assert isinstance(error, ValueError)
    assert message in str(error)
    assert rpc.calls == []
    assert db.sessions == []
    assert "Got exception, stopping task" in log.text


def test_missing_project_fails_without_a_session(run):
    db = SpyDb()

    _, error, rpc = run("project_id=99", db, projects=[make_project(1)])

    assert str(error) == "Project 99 not found"
    assert rpc.calls == [{"project_id": 99}]
    assert db.sessions == []


def test_unprovisioned_project_points_to_the_other_task(run):
    db = SpyDb()

    _, error, _ = run('{"project_id": 5}', db, projects=[make_project(5, create_success=False)])

    assert str(error) == "Project 5 was not provisioned successfully; use create_tables_for_failed"
    assert db.sessions == []


def test_shared_pass_failure_skips_every_project_and_fails_the_task(run):
    class BrokenSharedDb(SpyDb):
        def get_session(self, project_id=None):
            self.sessions.append(project_id)
            raise ConnectionError("db is down")

    db = BrokenSharedDb()

    log, error, _ = run("", db, projects=[make_project(1), make_project(2)])

    assert "shared: failed: ConnectionError: db is down" in log.text
    assert "projects: 2 skipped (shared pass failed)" in log.text
    assert "skipped=2" in log.text
    assert db.sessions == [None]
    assert isinstance(error, RuntimeError)


# --- planner, guard and apply on real PostgreSQL ---


def build_plain_tables():
    shared = sa.MetaData()
    sa.Table("shared_a", shared, sa.Column("id", sa.Integer, primary_key=True), schema=SHARED)
    tenant = sa.MetaData(schema=TENANT)
    sa.Table("alpha", tenant, sa.Column("id", sa.Integer, primary_key=True))
    sa.Table(
        "beta", tenant,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("alpha_id", sa.ForeignKey(f"{TENANT}.alpha.id"), index=True),
    )
    return shared, tenant


@pytest.fixture(name="engine")
def create_throwaway_database():
    name = "elitea_test_create_tables_{}".format(uuid.uuid4().hex[:8])
    admin = sa.create_engine(DSN, isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(sa.text(f'CREATE DATABASE "{name}"'))
    url = admin.url.set(database=name)
    bootstrap = sa.create_engine(url, isolation_level="AUTOCOMMIT")
    with bootstrap.connect() as connection:
        # Production resolves unqualified names to the schema named after the role ("$user")
        connection.execute(sa.text(f'CREATE SCHEMA "{url.username}"'))
        for schema in (SHARED, "p_1", "p_2", "p_3"):
            connection.execute(sa.text(f"CREATE SCHEMA {schema}"))
    bootstrap.dispose()
    target = sa.create_engine(url)
    try:
        yield target
    finally:
        target.dispose()
        with admin.connect() as connection:
            connection.execute(sa.text(f'DROP DATABASE "{name}" WITH (FORCE)'))
        admin.dispose()


def list_tables(engine, schema):
    return sorted(sa.inspect(engine).get_table_names(schema=schema))


def list_types_and_sequences(engine):
    """Enum types and standalone sequences; the serial sequences owned by id columns are left out."""
    with engine.connect() as connection:
        rows = connection.execute(sa.text(
            "SELECT n.nspname || '.' || t.typname FROM pg_type t "
            "JOIN pg_namespace n ON n.oid = t.typnamespace WHERE t.typtype = 'e' "
            "UNION ALL SELECT sequence_schema || '.' || sequence_name FROM information_schema.sequences "
            "WHERE sequence_name NOT LIKE '%\\_id\\_seq'"
        ))
        return sorted(row[0] for row in rows)


def provision(engine, shared, tenant, project_ids):
    shared.create_all(engine)
    for project_id in project_ids:
        tenant.create_all(engine.execution_options(schema_translate_map={TENANT: f"p_{project_id}"}))


def drop(engine, qualified_table):
    with engine.begin() as connection:
        connection.execute(sa.text(f"DROP TABLE {qualified_table} CASCADE"))


@needs_postgres
def test_single_project_dry_run_lists_the_missing_table_and_creates_nothing(run, engine):
    shared, tenant = build_plain_tables()
    provision(engine, shared, tenant, [1, 2])
    drop(engine, "p_1.beta")
    drop(engine, "p_2.beta")

    log, error, rpc = run("project_id=1", PostgresDb(engine, shared, tenant), projects=[make_project(1), make_project(2)])

    assert error is None
    assert "create_tables: scope=project 1; mode=DRY RUN; requested_by=7" in log.text
    assert "shared: up to date" in log.text
    assert "project 1: would create [beta]" in log.text
    assert "Done: projects planned=1 applied=0 up_to_date=0 skipped=0 stopped=0 failed=0; shared planned=0 applied=0" in log.text
    assert log.lines[-2] == "Dry run: nothing written; re-run with dry_run=false to apply"
    assert rpc.calls == [{"project_id": 1}]
    assert list_tables(engine, "p_1") == ["alpha"]
    assert list_tables(engine, "p_2") == ["alpha"]


@needs_postgres
def test_single_project_apply_creates_only_that_projects_table(run, engine):
    shared, tenant = build_plain_tables()
    provision(engine, shared, tenant, [1, 2])
    drop(engine, "p_1.beta")
    drop(engine, "p_2.beta")
    db = PostgresDb(engine, shared, tenant)

    log, error, _ = run('{"project_id": "1", "dry_run": false}', db, projects=[make_project(1), make_project(2)])

    assert error is None
    assert "create_tables: scope=project 1; mode=APPLY; requested_by=7" in log.text
    assert "project 1: created [beta]" in log.text
    assert "planned=1 applied=1" in log.text
    assert "Dry run" not in log.text
    assert db.sessions == [None, 1]
    assert list_tables(engine, "p_1") == ["alpha", "beta"]
    assert list_tables(engine, "p_2") == ["alpha"]
    assert [index["name"] for index in sa.inspect(engine).get_indexes("beta", schema="p_1")] == ["ix_tenant_beta_alpha_id"]


@needs_postgres
def test_single_project_apply_reports_pending_shared_tables_and_leaves_them(run, engine):
    shared, tenant = build_plain_tables()
    provision(engine, shared, tenant, [1])
    drop(engine, f"{SHARED}.shared_a")
    drop(engine, "p_1.beta")

    log, error, _ = run("project_id=1;dry_run=false", PostgresDb(engine, shared, tenant), projects=[make_project(1)])

    assert error is None
    assert "shared: not applied in single-project mode (1 pending: shared_a); run with project_id=all" in log.text
    assert "shared planned=1 applied=0" in log.text
    assert list_tables(engine, SHARED) == []
    assert list_tables(engine, "p_1") == ["alpha", "beta"]


@needs_postgres
def test_empty_param_previews_shared_and_all_eligible_projects(run, engine):
    shared, tenant = build_plain_tables()
    provision(engine, shared, tenant, [1, 2, 3])
    drop(engine, f"{SHARED}.shared_a")
    drop(engine, "p_1.beta")
    drop(engine, "p_3.alpha")
    db = PostgresDb(engine, shared, tenant)

    log, error, rpc = run("", db, projects=[make_project(1), make_project(2), make_project(3, create_success=False)])

    assert error is None
    assert "create_tables: scope=all (2 eligible projects); mode=DRY RUN" in log.text
    assert "shared: would create [shared_a]" in log.text
    assert "project 1: would create [beta]" in log.text
    assert "project 2" not in log.text
    assert "project 3" not in log.text
    assert "Done: projects planned=1 applied=0 up_to_date=1 skipped=0 stopped=0 failed=0; shared planned=1 applied=0" in log.text
    assert rpc.calls == [{"filter_": {"create_success": True}}]
    assert list_tables(engine, SHARED) == []
    assert list_tables(engine, "p_1") == ["alpha"]


@needs_postgres
def test_all_apply_creates_shared_then_every_project(run, engine):
    shared, tenant = build_plain_tables()
    provision(engine, shared, tenant, [1, 2])
    drop(engine, f"{SHARED}.shared_a")
    drop(engine, "p_1.beta")
    drop(engine, "p_2.alpha")

    log, error, _ = run("project_id=ALL; dry_run=FALSE", PostgresDb(engine, shared, tenant), projects=[make_project(1), make_project(2)])

    assert error is None
    assert "shared: created [shared_a]" in log.text
    assert "project 1: created [beta]" in log.text
    assert "project 2: created [alpha]" in log.text
    assert "Done: projects planned=2 applied=2 up_to_date=0 skipped=0 stopped=0 failed=0; shared planned=1 applied=1" in log.text
    assert list_tables(engine, SHARED) == ["shared_a"]
    assert list_tables(engine, "p_1") == list_tables(engine, "p_2") == ["alpha", "beta"]


@needs_postgres
def test_one_failing_project_does_not_stop_the_others_and_fails_the_task(run, engine):
    shared, tenant = build_plain_tables()
    provision(engine, shared, tenant, [1, 3])
    drop(engine, "p_1.beta")
    drop(engine, "p_3.beta")
    with engine.begin() as connection:
        connection.execute(sa.text("DROP SCHEMA p_2 CASCADE"))

    log, error, _ = run(
        "dry_run=false", PostgresDb(engine, shared, tenant),
        projects=[make_project(1), make_project(2), make_project(3)],
    )

    assert "project 1: created [beta]" in log.text
    assert "project 2: failed: ProgrammingError:" in log.text
    assert "project 3: created [beta]" in log.text
    assert "planned=2 applied=2 up_to_date=0 skipped=0 stopped=0 failed=1" in log.text
    assert isinstance(error, RuntimeError)
    assert str(error) == "create_tables: 1 project(s) failed: [2]"
    assert list_tables(engine, "p_3") == ["alpha", "beta"]


@needs_postgres
def test_up_to_date_project_gets_no_guard_and_no_create_all(run, engine, db_tasks, monkeypatch):
    shared, tenant = build_plain_tables()
    provision(engine, shared, tenant, [1])
    calls = []
    monkeypatch.setattr(db_tasks.schema_tables, "find_ddl_outside_schema", lambda *a, **k: calls.append("guard"))
    monkeypatch.setattr(tenant, "create_all", lambda *a, **k: calls.append("tenant create_all"))
    monkeypatch.setattr(shared, "create_all", lambda *a, **k: calls.append("shared create_all"))

    log, error, _ = run("dry_run=false", PostgresDb(engine, shared, tenant), projects=[make_project(1)])

    assert error is None
    assert calls == []
    assert "shared: up to date" in log.text
    assert "up_to_date=1" in log.text
    assert "project 1" not in log.text


class WrappedEnum(sa.TypeDecorator):
    impl = sa.Enum
    cache_ok = True


def build_tenant_with_offender(*columns, extra_table=None):
    tenant = sa.MetaData(schema=TENANT)
    sa.Table("alpha", tenant, sa.Column("id", sa.Integer, primary_key=True))
    sa.Table("offender", tenant, sa.Column("id", sa.Integer, primary_key=True), *columns)
    if extra_table is not None:
        extra_table(tenant)
    return tenant


def add_unplanned_enum_table(tenant):
    sa.Table(
        "alpha_existing", tenant,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("kind", sa.Enum("a", "b", name="kind_enum")),
    )


OUT_OF_SCHEMA_CASES = {
    "native enum": lambda: build_tenant_with_offender(sa.Column("kind", sa.Enum("a", "b", name="kind_enum"))),
    "array of enum": lambda: build_tenant_with_offender(sa.Column("kinds", postgresql.ARRAY(sa.Enum("a", "b", name="kind_enum")))),
    "type decorator over enum": lambda: build_tenant_with_offender(sa.Column("kind", WrappedEnum("a", "b", name="kind_enum"))),
    "enum variant": lambda: build_tenant_with_offender(
        sa.Column("kind", sa.String().with_variant(sa.Enum("a", "b", name="kind_enum"), "postgresql")),
    ),
    "enum on an unplanned table": lambda: build_tenant_with_offender(extra_table=add_unplanned_enum_table),
}


def provision_offender_case(engine, tenant):
    """p_1 has every table but 'offender'; an existing table with an enum column was created without its type."""
    with engine.begin() as connection:
        connection.execute(sa.text("CREATE TABLE p_1.alpha (id integer PRIMARY KEY)"))
        if "tenant.alpha_existing" in tenant.tables:
            connection.execute(sa.text("CREATE TABLE p_1.alpha_existing (id integer PRIMARY KEY, kind text)"))


@needs_postgres
@pytest.mark.parametrize("case", sorted(OUT_OF_SCHEMA_CASES))
@pytest.mark.parametrize("param", ["project_id=1", "project_id=1;dry_run=false"])
def test_single_project_stops_before_creating_a_type_outside_its_schema(run, engine, case, param):
    shared, _ = build_plain_tables()
    tenant = OUT_OF_SCHEMA_CASES[case]()
    provision_offender_case(engine, tenant)
    default_schema = engine.url.username
    before = list_tables(engine, "p_1")

    log, error, _ = run(param, PostgresDb(engine, shared, tenant), projects=[make_project(1)])

    assert (
        f"project 1: needs a shared-schema change first: CreateEnumType kind_enum (→ {default_schema}); "
        "run with project_id=all; not created: [offender]"
    ) in log.text
    assert "stopped=1 failed=0" in log.text
    assert str(error) == "create_tables: 1 project(s) need a shared-schema change first: [1]"
    assert list_types_and_sequences(engine) == []
    assert list_tables(engine, "p_1") == before


@needs_postgres
def test_single_project_stops_before_creating_a_sequence_outside_its_schema(run, engine):
    shared, _ = build_plain_tables()
    tenant = build_tenant_with_offender(sa.Column("n", sa.Integer, sa.Sequence("offender_seq")))
    provision_offender_case(engine, tenant)

    log, error, _ = run("project_id=1;dry_run=false", PostgresDb(engine, shared, tenant), projects=[make_project(1)])

    assert f"CreateSequence offender_seq (→ {engine.url.username})" in log.text
    assert isinstance(error, RuntimeError)
    assert list_types_and_sequences(engine) == []
    assert list_tables(engine, "p_1") == ["alpha"]


@needs_postgres
@pytest.mark.parametrize("case", sorted(OUT_OF_SCHEMA_CASES))
def test_single_project_passes_once_the_shared_type_exists(run, engine, case):
    shared, _ = build_plain_tables()
    tenant = OUT_OF_SCHEMA_CASES[case]()
    provision_offender_case(engine, tenant)
    with engine.begin() as connection:
        connection.execute(sa.text("CREATE TYPE kind_enum AS ENUM ('a', 'b')"))

    log, error, _ = run("project_id=1;dry_run=false", PostgresDb(engine, shared, tenant), projects=[make_project(1)])

    assert error is None
    assert "project 1: created [offender]" in log.text
    assert "also created" not in log.text
    assert "offender" in list_tables(engine, "p_1")


@needs_postgres
def test_all_mode_reports_the_shared_type_and_creates_it(run, engine):
    shared, _ = build_plain_tables()
    tenant = OUT_OF_SCHEMA_CASES["native enum"]()
    provision_offender_case(engine, tenant)
    with engine.begin() as connection:
        connection.execute(sa.text("CREATE TABLE p_2.alpha (id integer PRIMARY KEY)"))
    default_schema = engine.url.username
    db = PostgresDb(engine, shared, tenant)

    preview, preview_error, _ = run("project_id=all", db, projects=[make_project(1), make_project(2)])

    assert preview_error is None
    assert "project 1: would create [offender]" in preview.text
    assert f"project 1: would also create CreateEnumType kind_enum (→ {default_schema})" in preview.text
    assert list_types_and_sequences(engine) == []

    applied, apply_error, _ = run("project_id=all;dry_run=false", db, projects=[make_project(1), make_project(2)])

    assert apply_error is None
    assert f"project 1: also created CreateEnumType kind_enum (→ {default_schema})" in applied.text
    assert "project 2: created [offender]" in applied.text
    assert "project 2: also created" not in applied.text
    assert list_types_and_sequences(engine) == [f"{default_schema}.kind_enum"]


def build_in_schema_tenant():
    tenant = sa.MetaData(schema=TENANT)
    sa.Table(
        "in_schema", tenant,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("flag", sa.Boolean),
        sa.Column("soft_kind", sa.Enum("a", "b", name="soft_kind", native_enum=False)),
        sa.Column("own_kind", sa.Enum("a", "b", name="own_kind", inherit_schema=True)),
        sa.Column("note", sa.String, comment="a commented column"),
    )
    sa.Table(
        "cycle_a", tenant,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("b_id", sa.Integer, sa.ForeignKey(f"{TENANT}.cycle_b.id", use_alter=True, name="fk_a_b")),
    )
    sa.Table(
        "cycle_b", tenant,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("a_id", sa.Integer, sa.ForeignKey(f"{TENANT}.cycle_a.id")),
    )
    return tenant


@needs_postgres
def test_objects_that_stay_inside_the_project_schema_pass_the_guard_and_are_applied(run, engine):
    shared, _ = build_plain_tables()
    tenant = build_in_schema_tenant()

    log, error, _ = run("project_id=1;dry_run=false", PostgresDb(engine, shared, tenant), projects=[make_project(1)])

    assert error is None, log.text
    assert "needs a shared-schema change first" not in log.text
    assert list_tables(engine, "p_1") == ["cycle_a", "cycle_b", "in_schema"]
    assert list_types_and_sequences(engine) == ["p_1.own_kind"]
    assert sa.inspect(engine).get_foreign_keys("cycle_a", schema="p_1")[0]["name"] == "fk_a_b"
    assert list_tables(engine, "p_2") == []
