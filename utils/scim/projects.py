""" Every SCIM group is a protected team project (#5202).

``sync_all`` makes the platform match the SCIM tables:
- a group without a project gets one (name from protocol.project_name_for), registered as protected;
- a renamed group renames its project; a removed group suspends its project and unprotects it;
- each project's SCIM members are the group's effective members (direct members plus those of nested
  groups, from ``admin_scim_group_edge``): missing ones are added as viewer, ones SCIM granted that left
  are removed. Members SCIM did not add (system user, ...) are never touched;
- users deactivated or deleted in the IdP are suspended, and unsuspended again only if SCIM suspended them.

``platform`` gives: find_user, ensure_user(email), set_user_suspended, is_user_suspended,
create_project(name), rename_project, set_project_suspended,
project_user_ids, add_member(project_id, user_id, role), remove_member, record_audit.
"""
import threading
from datetime import datetime, timezone

from sqlalchemy import select

from pylon.core.tools import log  # pylint: disable=E0401

from ...models.scim import (
    ScimGroup, ScimGroupEdge, ScimGroupMember, ScimMembershipGrant, ScimProject, ScimSetting, ScimUser,
)
from . import protocol
from .service import GROUP_ACTIVE, GROUP_ERROR, GROUP_PENDING, GROUP_REMOVED, audit_event

DEFAULT_ROLE = "viewer"
GRAPH_STATUS_KEY = "graph_status"


def _now():
    return datetime.now(timezone.utc)


def effective_members(group_external_ids, direct, edges) -> dict:
    """ {group external id: set of user ids} with members of nested groups included, cycle-safe """
    result = {}
    for root in group_external_ids:
        seen, stack, members = set(), [root], set()
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            members |= direct.get(current, set())
            stack.extend(edges.get(current, ()))
        result[root] = members
    return result


class ProjectSync:
    def __init__(self, get_session, platform):
        self.get_session = get_session
        self.platform = platform
        self._lock = threading.Lock()

    def _audit(self, *args, **kwargs):
        try:
            self.platform.record_audit(audit_event(*args, **kwargs))
        except Exception:  # pylint: disable=W0703
            log.exception("SCIM audit record failed")

    #
    # Nesting
    #

    def set_edges(self, edges: dict):
        """ Replace the stored nesting: {parent external id: [child external ids]} """
        with self.get_session() as session:
            session.query(ScimGroupEdge).delete()
            for parent, children in edges.items():
                for child in dict.fromkeys(children):
                    if child != parent:
                        session.add(ScimGroupEdge(parent_external_id=parent, child_external_id=child))
            session.commit()

    def pull_edges(self, fetch_children):
        """ fetch_children([external ids]) -> {parent: [children]}; on failure the stored nesting stays """
        with self.get_session() as session:
            external_ids = [x for x in session.scalars(select(ScimGroup.external_id).where(
                ScimGroup.status != GROUP_REMOVED, ScimGroup.external_id.is_not(None)))]
        try:
            edges = fetch_children(external_ids)
        except Exception as exc:  # pylint: disable=W0703
            log.warning("SCIM: reading group nesting failed: %s", exc)
            self._set_graph_status(str(exc)[:500])
            self._audit("SCIM_GRAPH_FAILED", "graph", outcome="failed")
            return False
        self.set_edges(edges)
        self._set_graph_status(None)
        return True

    def _set_graph_status(self, error):
        with self.get_session() as session:
            row = session.get(ScimSetting, GRAPH_STATUS_KEY) or ScimSetting(key=GRAPH_STATUS_KEY)
            previous = row.value or {}
            row.value = {
                "error": error,
                "last_attempt_at": _now().isoformat(),
                "last_success_at": previous.get("last_success_at") if error else _now().isoformat(),
            }
            row.updated_at = _now()
            session.merge(row)
            session.commit()

    def graph_status(self):
        with self.get_session() as session:
            row = session.get(ScimSetting, GRAPH_STATUS_KEY)
            return (row.value if row and row.value else None) or {
                "error": None, "last_attempt_at": None, "last_success_at": None}

    #
    # Sync
    #

    def sync_all(self) -> dict:
        """ One pass over every group; serialized so two passes never create the same project """
        with self._lock:
            result = {"created": 0, "renamed": 0, "suspended": 0, "added": 0, "removed": 0, "errors": 0}
            self._sync_users()
            self._sync_projects(result)
            self._sync_members(result)
            return result

    def _sync_users(self):
        """ Suspend accounts of users deactivated or deleted in the IdP; undo only our own suspension """
        with self.get_session() as session:
            rows = session.scalars(select(ScimUser).where(ScimUser.elitea_user_id.is_not(None))).all()
            for row in rows:
                inactive = row.deleted or not row.active
                try:
                    if inactive and not row.suspended_by_scim:
                        if not self.platform.is_user_suspended(row.elitea_user_id):
                            self.platform.set_user_suspended(row.elitea_user_id, True)
                            row.suspended_by_scim = True
                            self._audit("SCIM_USER_SUSPENDED", f"user:{row.elitea_user_id}")
                    elif not inactive and row.suspended_by_scim:
                        self.platform.set_user_suspended(row.elitea_user_id, False)
                        row.suspended_by_scim = False
                        self._audit("SCIM_USER_UNSUSPENDED", f"user:{row.elitea_user_id}")
                except Exception:  # pylint: disable=W0703
                    log.exception("SCIM: suspending user %s failed", row.elitea_user_id)
            session.commit()

    def _sync_projects(self, result):
        with self.get_session() as session:
            groups = session.scalars(select(ScimGroup)).all()
            for group in groups:
                try:
                    if group.status == GROUP_REMOVED:
                        self._retire(session, group, result)
                    elif group.project_id is None:
                        self._create(session, group, result)
                    else:
                        self._rename(session, group, result)
                except Exception as exc:  # pylint: disable=W0703
                    log.exception("SCIM: project of group %s failed", group.id)
                    group.status = GROUP_ERROR
                    group.error = str(exc)[:500]
                    result["errors"] += 1
                session.commit()

    def _create(self, session, group, result):
        name = protocol.project_name_for(group.display_name)
        project_id = self.platform.create_project(name)
        if not project_id:
            raise RuntimeError("The project could not be created")
        group.project_id = project_id
        group.status = GROUP_ACTIVE
        group.error = None
        session.merge(ScimProject(project_id=project_id, group_id=group.id, protected=True, created_at=_now()))
        result["created"] += 1
        self._audit("SCIM_PROJECT_CREATED", f"scim_group:{group.id};name:{name}", project_id=project_id)

    def _rename(self, session, group, result):
        if group.status == GROUP_ERROR:
            group.status, group.error = GROUP_ACTIVE, None
        current = self._project_name(group.project_id)
        wanted = protocol.project_name_for(group.display_name)
        if current is not None and wanted != current:
            self.platform.rename_project(group.project_id, wanted)
            result["renamed"] += 1
            self._audit("SCIM_PROJECT_RENAMED", f"scim_group:{group.id};name:{wanted}", project_id=group.project_id)

    def _project_name(self, project_id):
        names = getattr(self.platform, "project_name", None)
        if names is not None:
            return names(project_id)
        projects = getattr(self.platform, "projects", {})
        return (projects.get(project_id) or {}).get("name")

    def _retire(self, session, group, result):
        if group.project_id is None:
            return
        registry = session.get(ScimProject, group.project_id)
        if registry is None or not registry.protected:
            return
        self.platform.set_project_suspended(group.project_id, True)
        registry.protected = False
        session.query(ScimMembershipGrant).filter(ScimMembershipGrant.group_id == group.id).delete()
        result["suspended"] += 1
        self._audit("SCIM_PROJECT_SUSPENDED", f"scim_group:{group.id}", project_id=group.project_id)

    def _sync_members(self, result):
        with self.get_session() as session:
            groups = session.scalars(select(ScimGroup).where(
                ScimGroup.status == GROUP_ACTIVE, ScimGroup.project_id.is_not(None))).all()
            if not groups:
                return
            external = {g.id: (g.external_id or g.id) for g in groups}
            all_groups = session.scalars(select(ScimGroup).where(ScimGroup.status != GROUP_REMOVED)).all()
            key_of = {g.id: (g.external_id or g.id) for g in all_groups}
            direct = {}
            for group_id, user_id in session.execute(
                    select(ScimGroupMember.group_id, ScimGroupMember.user_id)
                    .join(ScimUser, ScimUser.id == ScimGroupMember.user_id)
                    .where(ScimUser.active.is_(True), ScimUser.deleted.is_(False))):
                if group_id in key_of:
                    direct.setdefault(key_of[group_id], set()).add(user_id)
            known = set(key_of.values())
            edges = {}
            for edge in session.scalars(select(ScimGroupEdge)):
                if edge.parent_external_id in known and edge.child_external_id in known:
                    edges.setdefault(edge.parent_external_id, []).append(edge.child_external_id)
            wanted = effective_members(list(external.values()), direct, edges)
            users = {u.id: u for u in session.scalars(select(ScimUser))}
            plans = [(g.id, g.project_id, wanted.get(external[g.id], set())) for g in groups]
        for group_id, project_id, scim_user_ids in plans:
            self._sync_project_members(group_id, project_id, scim_user_ids, users, result)

    def _sync_project_members(self, group_id, project_id, scim_user_ids, users, result):
        with self.get_session() as session:
            granted = {g.user_id for g in session.scalars(select(ScimMembershipGrant).where(
                ScimMembershipGrant.project_id == project_id, ScimMembershipGrant.group_id == group_id))}
        in_project = set(self.platform.project_user_ids(project_id))
        keep = set()
        for scim_user_id in scim_user_ids:
            user = users.get(scim_user_id)
            if user is None or not user.email:
                continue
            try:
                user_id = user.elitea_user_id or self.platform.ensure_user(user.email)
            except Exception:  # pylint: disable=W0703
                log.exception("SCIM: account for %s could not be created", scim_user_id)
                result["errors"] += 1
                continue
            keep.add(user_id)
            if not user.elitea_user_id:
                self._link_user(scim_user_id, user_id)
                user.elitea_user_id = user_id
            if user_id in in_project and user_id not in granted:
                continue   # a member before SCIM synced the project: their role stays, never removed by SCIM
            if user_id not in in_project:
                try:
                    self.platform.add_member(project_id, user_id, DEFAULT_ROLE)
                except Exception:  # pylint: disable=W0703
                    log.exception("SCIM: adding %s to project %s failed", user_id, project_id)
                    result["errors"] += 1
                    continue
                result["added"] += 1
                self._audit("SCIM_MEMBER_ADDED", f"user:{user_id};role:{DEFAULT_ROLE}", project_id=project_id)
            self._grant(project_id, user_id, group_id)
        for user_id in granted - keep:
            try:
                self.platform.remove_member(project_id, user_id)
            except Exception:  # pylint: disable=W0703
                log.exception("SCIM: removing %s from project %s failed", user_id, project_id)
                result["errors"] += 1
                continue
            self._ungrant(project_id, user_id, group_id)
            result["removed"] += 1
            self._audit("SCIM_MEMBER_REMOVED", f"user:{user_id}", project_id=project_id)

    def _link_user(self, scim_user_id, user_id):
        with self.get_session() as session:
            row = session.get(ScimUser, scim_user_id)
            if row is not None and not row.elitea_user_id:
                row.elitea_user_id = user_id
                session.commit()

    def _grant(self, project_id, user_id, group_id):
        with self.get_session() as session:
            exists = session.scalars(select(ScimMembershipGrant.id).where(
                ScimMembershipGrant.project_id == project_id, ScimMembershipGrant.user_id == user_id,
                ScimMembershipGrant.group_id == group_id)).first()
            if exists is None:
                session.add(ScimMembershipGrant(project_id=project_id, user_id=user_id, group_id=group_id,
                                                granted_at=_now()))
                session.commit()

    def _ungrant(self, project_id, user_id, group_id):
        with self.get_session() as session:
            session.query(ScimMembershipGrant).filter(
                ScimMembershipGrant.project_id == project_id, ScimMembershipGrant.user_id == user_id,
                ScimMembershipGrant.group_id == group_id).delete()
            session.commit()

    #
    # Administration
    #

    def overview(self) -> list:
        with self.get_session() as session:
            groups = session.scalars(select(ScimGroup).order_by(ScimGroup.display_name)).all()
            key_of = {g.id: (g.external_id or g.id) for g in groups if g.status != GROUP_REMOVED}
            name_of = {key: g.display_name for g in groups if g.id in key_of for key in [key_of[g.id]]}
            direct = {}
            for group_id, user_id in session.execute(select(ScimGroupMember.group_id, ScimGroupMember.user_id)):
                if group_id in key_of:
                    direct.setdefault(key_of[group_id], set()).add(user_id)
            edges, parents = {}, {}
            for edge in session.scalars(select(ScimGroupEdge)):
                if edge.parent_external_id in name_of and edge.child_external_id in name_of:
                    edges.setdefault(edge.parent_external_id, []).append(edge.child_external_id)
                    parents.setdefault(edge.child_external_id, []).append(edge.parent_external_id)
            effective = effective_members(list(key_of.values()), direct, edges)
            rows = []
            for g in groups:
                key = key_of.get(g.id)
                rows.append({
                    "id": g.id, "display_name": g.display_name, "external_id": g.external_id,
                    "status": g.status, "error": g.error, "project_id": g.project_id,
                    "project_name": self._project_name(g.project_id) if g.project_id else None,
                    "member_count": len(direct.get(key, ())) if key else 0,
                    "effective_member_count": len(effective.get(key, ())) if key else 0,
                    "children": sorted(name_of[c] for c in edges.get(key, ())) if key else [],
                    "parents": sorted(name_of[p] for p in parents.get(key, ())) if key else [],
                    "last_activity_at": g.last_activity_at.isoformat() if g.last_activity_at else None,
                })
            return rows

    def pending_exists(self) -> bool:
        with self.get_session() as session:
            return session.scalars(select(ScimGroup.id).where(
                ScimGroup.status.in_([GROUP_PENDING, GROUP_ERROR]))).first() is not None
