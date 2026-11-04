""" SCIM provisioning wiring for the admin module (#5202): tables, bearer verifier, background project sync,
Microsoft Graph nesting pull """
import threading
from contextlib import contextmanager

from sqlalchemy import func, select

from pylon.core.tools import log  # pylint: disable=E0401
from tools import auth, db, this  # pylint: disable=E0401

from ...models.scim import TABLES, ScimSetting
from . import graph, tokens
from .guards import Guards
from .platform import Platform
from .projects import ProjectSync
from .service import ScimService

API_PATH = "/api/v2/admin/scim/"
SYNC_ADVISORY_LOCK_KEY = 5202000001
PROJECTS_CHANGED_EVENT = "admin_scim_projects_changed"
GRAPH_APP_KEY = "graph_oauth_app_id"
DEBOUNCE_S = 3


class ScimRuntime:
    def __init__(self, module, config: dict):
        self.module = module
        self.public_url = (config.get("public_url") or "").rstrip("/")
        self.platform = Platform(module)
        self.guards = Guards(db.get_session)
        self.sync = ProjectSync(db.get_session, self.platform, lock=self._replica_lock)
        self.sync.on_projects_changed = self._announce_projects_changed
        self.service = ScimService(db.get_session, self.platform, on_group_changed=self.request_sync,
                                   on_user_changed=self.request_sync, base_url=self.base_url())
        self._wake = threading.Event()
        self._pull_graph = threading.Event()
        self._full = threading.Event()
        self._stopped = threading.Event()
        self._worker = None

    def base_url(self):
        return f"{self.public_url}{API_PATH}administration"

    def start(self):
        db.get_shared_metadata().create_all(bind=db.engine, tables=[t.__table__ for t in TABLES])
        auth.register_bearer_verifier(
            tokens.PREFIX, tokens.make_verifier(self.service.verify_token, self.service_user_id, API_PATH))
        self._worker = threading.Thread(target=self._run, name="scim-project-sync", daemon=True)
        self._worker.start()
        self.request_sync(graph_pull=True, full=True)   # backfill: groups provisioned before their project existed
        log.info("SCIM provisioning enabled at %s", self.base_url())

    def stop(self):
        self._stopped.set()
        self._wake.set()
        try:
            auth.unregister_bearer_verifier(tokens.PREFIX)
        except Exception:  # pylint: disable=W0703
            pass

    def service_user_id(self):
        return self.platform.service_user_id()

    #
    # Replicas: one sync at a time, protected set refreshed everywhere
    #

    @staticmethod
    @contextmanager
    def _replica_lock():
        """ True while this replica holds the SCIM sync advisory lock; False (skip) when another one does """
        with db.engine.connect() as connection:
            try:
                acquired = bool(connection.execute(select(func.pg_try_advisory_lock(SYNC_ADVISORY_LOCK_KEY))).scalar())
            except Exception:  # pylint: disable=W0703
                log.exception("SCIM: sync lock is unreachable; skipping the pass")
                acquired = False
            try:
                yield acquired
            finally:
                if acquired:
                    try:
                        connection.execute(select(func.pg_advisory_unlock(SYNC_ADVISORY_LOCK_KEY)))
                    except Exception:  # pylint: disable=W0703
                        log.exception("SCIM: failed to release the sync lock")

    def _announce_projects_changed(self):
        self.guards.invalidate()
        self.module.context.event_manager.fire_event(PROJECTS_CHANGED_EVENT, {})

    def on_projects_changed_event(self):
        """ Another replica created, suspended or unprotected a SCIM project """
        self.guards.invalidate()

    def is_provisioner(self, user_id) -> bool:
        return user_id is not None and user_id == self.platform.service_user_id()

    #
    # Background sync
    #

    def request_sync(self, *_, graph_pull=False, full=False):
        """ Coalesced: many SCIM requests in a burst give one sync pass a few seconds later. SCIM writes sync
            only the groups they changed; ``full`` (schedule, Sync now, startup) re-checks every group """
        if graph_pull:
            self._pull_graph.set()
        if full:
            self._full.set()
        self._wake.set()

    def _run(self):
        while not self._stopped.is_set():
            self._wake.wait()
            if self._stopped.is_set():
                return
            self._stopped.wait(DEBOUNCE_S)
            self._wake.clear()
            try:
                if self._pull_graph.is_set():
                    self._pull_graph.clear()
                    self.pull_nesting()
                result = self.sync.sync_all(full=self._full.is_set())
                self._full.clear()
                log.info("SCIM project sync: %s", result)
            except Exception:  # pylint: disable=W0703
                log.exception("SCIM project sync failed")

    #
    # Graph nesting
    #

    def graph_app_id(self):
        with db.get_session() as session:
            row = session.get(ScimSetting, GRAPH_APP_KEY)
            return (row.value or {}).get("app_id") if row else None

    def set_graph_app_id(self, app_id):
        from .projects import _now  # pylint: disable=C0415
        with db.get_session() as session:
            session.merge(ScimSetting(key=GRAPH_APP_KEY, value={"app_id": app_id or None}, updated_at=_now()))
            session.commit()
        self.request_sync(graph_pull=True)

    def _graph_fetcher(self):
        app_id = self.graph_app_id()
        if not app_id:
            return None
        client = this.for_module("configurations").module.oauth_apps_app_only_client(app_id)
        token = graph.app_token(client["token_endpoint"], client["client_id"], client["client_secret"])
        return graph.fetcher(token)

    def pull_nesting(self) -> bool:
        try:
            fetch = self._graph_fetcher()
        except Exception as exc:  # pylint: disable=W0703
            return self.sync.pull_edges(lambda _ids, error=exc: (_ for _ in ()).throw(error))
        if fetch is None:
            return False   # nesting is off: groups sync flat with the last known edges (none by default)
        return self.sync.pull_edges(fetch)

    def check_graph(self) -> dict:
        try:
            fetch = self._graph_fetcher()
        except Exception as exc:  # pylint: disable=W0703
            return {"success": False, "message": str(exc)[:300]}
        if fetch is None:
            return {"success": False, "message": "No Microsoft Entra app is selected"}
        ok = self.sync.pull_edges(fetch)
        status = self.sync.graph_status()
        return {"success": ok, "message": status.get("error") or "Group nesting was read"}
