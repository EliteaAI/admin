""" Every SCIM group is a protected team project (#5202).

``sync_all`` makes the platform match the SCIM tables:
- a group without a project gets one (name from protocol.project_name_for), registered as protected;
- a renamed group renames its project; a removed group suspends its project and unprotects it;
- each project's SCIM members are the group's effective members (direct members plus those of nested
  groups, from ``admin_scim_group_edge``): missing ones are added as viewer, ones SCIM granted that left
  are removed. Members SCIM did not add (system user, ...) are never touched;
- users deactivated or deleted in the IdP are suspended, and unsuspended again only if SCIM suspended them.
  Platform admins and system users are never suspended by SCIM (a SCIM token must not lock out an admin).

``platform`` gives: find_user, ensure_user(email), set_user_suspended, is_user_suspended, is_protected_account,
project_name(project_id), create_project(name), rename_project, set_project_suspended,
project_user_ids, add_member(project_id, user_id, role), remove_member, clear_user_projects_cache(user_ids),
record_audit. No DB session is held while these run.
"""
import threading
from contextlib import contextmanager
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


@contextmanager
def _no_cross_process_lock():
    yield True


class ProjectSync:
    def __init__(self, get_session, platform, lock=None):
        self.get_session = get_session
        self.platform = platform
        self._lock = threading.Lock()
        # () -> context manager yielding True when this process may sync now (one replica at a time)
        self.lock = lock or _no_cross_process_lock
        # called after protected projects changed, so every replica drops its cached protected set
        self.on_projects_changed = lambda: None

    def _audit(self, *args, **kwargs):
        try:
            self.platform.record_audit(audit_event(*args, **kwargs))
        except Exception:  # pylint: disable=W0703
            log.exception("SCIM audit record failed")

    #
    # Nesting
    #

    def set_edges(self, edges: dict):
        """ Replace the stored nesting: {parent external id: [child external ids]}; the parent of every
            added or removed edge is marked for sync (its ancestors follow in _groups_to_sync) """
        wanted = {(parent, child) for parent, children in edges.items() for child in children if child != parent}
        with self.get_session() as session:
            current = {(e.parent_external_id, e.child_external_id) for e in session.scalars(select(ScimGroupEdge))}
            changed = wanted ^ current
            if not changed:
                return
            session.query(ScimGroupEdge).delete()
            for parent, child in sorted(wanted):
                session.add(ScimGroupEdge(parent_external_id=parent, child_external_id=child))
            touched = {parent for parent, _ in changed}
            session.query(ScimGroup).filter(ScimGroup.external_id.in_(touched)).update(
                {ScimGroup.dirty: True}, synchronize_session=False)
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

    def sync_all(self, full=False) -> dict:
        """ One pass. Only groups marked dirty unless ``full`` (schedule, Sync now). Serialized within the
            process by a lock and across pylon replicas by ``lock`` (a Postgres advisory lock in production):
            a replica that does not get it skips the pass, the holder will see the same dirty groups. """
        result = {"created": 0, "renamed": 0, "suspended": 0, "added": 0, "removed": 0, "errors": 0,
                  "skipped": False}
        with self._lock:
            with self.lock() as acquired:
                if not acquired:
                    return result | {"skipped": True}
                self._sync_users()
                groups = self._groups_to_sync(full)
                self._sync_projects(groups, result)
                self._sync_members(groups, result)
                self._clear_dirty(groups)
        if result["created"] or result["suspended"]:
            try:
                self.on_projects_changed()
            except Exception:  # pylint: disable=W0703
                log.exception("SCIM: protected-project change was not announced")
        return result

    def _groups_to_sync(self, full):
        """ Ids of the dirty groups (all when ``full``) plus every ancestor of them through nesting """
        with self.get_session() as session:
            groups = session.execute(select(ScimGroup.id, ScimGroup.external_id, ScimGroup.dirty)).all()
            edges = [(e.parent_external_id, e.child_external_id) for e in session.scalars(select(ScimGroupEdge))]
        key_of = {g.id: (g.external_id or g.id) for g in groups}
        id_of = {key: gid for gid, key in key_of.items()}
        picked = {g.id for g in groups if full or g.dirty}
        parents = {}
        for parent, child in edges:
            parents.setdefault(child, []).append(parent)
        stack = [key_of[g] for g in picked]
        while stack:
            for parent in parents.get(stack.pop(), ()):
                if parent in id_of and id_of[parent] not in picked:
                    picked.add(id_of[parent])
                    stack.append(parent)
        return picked

    def _clear_dirty(self, group_ids):
        """ Clear the flag of groups that synced cleanly; groups that failed stay dirty for the next pass """
        with self.get_session() as session:
            session.query(ScimGroup).filter(ScimGroup.id.in_(group_ids), ScimGroup.status != GROUP_ERROR).update(
                {ScimGroup.dirty: False}, synchronize_session=False)
            session.commit()

    def _sync_users(self):
        """ Suspend accounts of users deactivated or deleted in the IdP; undo only our own suspension.
            Reads only the rows that need a change, and holds no session across platform calls """
        with self.get_session() as session:
            rows = session.execute(select(ScimUser.id, ScimUser.elitea_user_id, ScimUser.suspended_by_scim).where(
                ScimUser.elitea_user_id.is_not(None),
                ((ScimUser.deleted.is_(True) | ScimUser.active.is_(False)) & ScimUser.suspended_by_scim.is_(False))
                | ((ScimUser.deleted.is_(False) & ScimUser.active.is_(True)) & ScimUser.suspended_by_scim.is_(True))
            )).all()
        for row in rows:
            suspend = not row.suspended_by_scim
            try:
                if suspend:
                    if self.platform.is_protected_account(row.elitea_user_id):
                        continue
                    if self.platform.is_user_suspended(row.elitea_user_id):
                        continue   # someone else suspended it: not ours to undo later
                self.platform.set_user_suspended(row.elitea_user_id, suspend)
            except Exception:  # pylint: disable=W0703
                log.exception("SCIM: suspending user %s failed", row.elitea_user_id)
                continue
            with self.get_session() as session:
                session.query(ScimUser).filter(ScimUser.id == row.id).update(
                    {ScimUser.suspended_by_scim: suspend}, synchronize_session=False)
                session.commit()
            self._audit("SCIM_USER_SUSPENDED" if suspend else "SCIM_USER_UNSUSPENDED", f"user:{row.elitea_user_id}")

    def _sync_projects(self, group_ids, result):
        with self.get_session() as session:
            groups = session.execute(select(
                ScimGroup.id, ScimGroup.display_name, ScimGroup.status, ScimGroup.project_id,
            ).where(ScimGroup.id.in_(group_ids))).all()
        for group in groups:
            try:
                if group.status == GROUP_REMOVED:
                    self._retire(group, result)
                elif group.project_id is None:
                    self._create(group, result)
                else:
                    self._rename(group, result)
            except Exception as exc:  # pylint: disable=W0703
                log.exception("SCIM: project of group %s failed", group.id)
                self._update_group(group.id, status=GROUP_ERROR, error=str(exc)[:500])
                result["errors"] += 1

    def _update_group(self, group_id, **values):
        with self.get_session() as session:
            session.query(ScimGroup).filter(ScimGroup.id == group_id).update(
                {getattr(ScimGroup, k): v for k, v in values.items()}, synchronize_session=False)
            session.commit()

    def _create(self, group, result):
        with self.get_session() as session:
            if session.scalar(select(ScimGroup.project_id).where(ScimGroup.id == group.id)) is not None:
                return   # another replica created it after this pass read the group
        name = protocol.project_name_for(group.display_name)
        project_id = self.platform.create_project(name)
        if not project_id:
            raise RuntimeError("The project could not be created")
        with self.get_session() as session:
            row = session.get(ScimGroup, group.id)
            row.project_id, row.status, row.error = project_id, GROUP_ACTIVE, None
            session.merge(ScimProject(project_id=project_id, group_id=group.id, protected=True, created_at=_now()))
            session.commit()
        result["created"] += 1
        self._audit("SCIM_PROJECT_CREATED", f"scim_group:{group.id};name:{name}", project_id=project_id)

    def _rename(self, group, result):
        if group.status == GROUP_ERROR:
            self._update_group(group.id, status=GROUP_ACTIVE, error=None)
        current = self._project_name(group.project_id)
        wanted = protocol.project_name_for(group.display_name)
        if current is not None and wanted != current:
            self.platform.rename_project(group.project_id, wanted)
            result["renamed"] += 1
            self._audit("SCIM_PROJECT_RENAMED", f"scim_group:{group.id};name:{wanted}", project_id=group.project_id)

    def _project_name(self, project_id):
        return self.platform.project_name(project_id)

    def _retire(self, group, result):
        if group.project_id is None:
            return
        with self.get_session() as session:
            registry = session.get(ScimProject, group.project_id)
            if registry is None or not registry.protected:
                return
        self.platform.set_project_suspended(group.project_id, True)
        with self.get_session() as session:
            session.query(ScimProject).filter(ScimProject.project_id == group.project_id).update(
                {ScimProject.protected: False}, synchronize_session=False)
            session.query(ScimMembershipGrant).filter(ScimMembershipGrant.group_id == group.id).delete()
            session.commit()
        result["suspended"] += 1
        self._audit("SCIM_PROJECT_SUSPENDED", f"scim_group:{group.id}", project_id=group.project_id)

    def _sync_members(self, group_ids, result):
        """ Diff each picked group's project against its effective members; reads only the rows involved """
        with self.get_session() as session:
            all_groups = session.execute(select(ScimGroup.id, ScimGroup.external_id, ScimGroup.status,
                                                ScimGroup.project_id)).all()
            key_of = {g.id: (g.external_id or g.id) for g in all_groups if g.status != GROUP_REMOVED}
            targets = [g for g in all_groups
                       if g.id in group_ids and g.status == GROUP_ACTIVE and g.project_id is not None]
            if not targets:
                return
            edges = {}
            for edge in session.scalars(select(ScimGroupEdge)):
                if edge.parent_external_id in key_of.values() and edge.child_external_id in key_of.values():
                    edges.setdefault(edge.parent_external_id, []).append(edge.child_external_id)
            needed = set()
            stack = [key_of[g.id] for g in targets]
            while stack:
                key = stack.pop()
                if key not in needed:
                    needed.add(key)
                    stack.extend(edges.get(key, ()))
            needed_ids = [gid for gid, key in key_of.items() if key in needed]
            direct = {}
            members = session.execute(
                select(ScimGroupMember.group_id, ScimUser.id, ScimUser.email, ScimUser.elitea_user_id)
                .join(ScimUser, ScimUser.id == ScimGroupMember.user_id)
                .where(ScimGroupMember.group_id.in_(needed_ids), ScimUser.active.is_(True),
                       ScimUser.deleted.is_(False))).all()
            users = {}
            for row in members:
                direct.setdefault(key_of[row.group_id], set()).add(row.id)
                users[row.id] = row
            wanted = effective_members([key_of[g.id] for g in targets], direct, edges)
            grants = {}
            for grant in session.scalars(select(ScimMembershipGrant).where(
                    ScimMembershipGrant.group_id.in_([g.id for g in targets]))):
                grants.setdefault(grant.group_id, set()).add(grant.user_id)
        for group in targets:
            self._sync_project_members(group.id, group.project_id, wanted.get(key_of[group.id], set()),
                                       users, grants.get(group.id, set()), result)

    def _sync_project_members(self, group_id, project_id, scim_user_ids, users, granted, result):
        in_project = set(self.platform.project_user_ids(project_id))
        keep, touched, new_links, new_grants = set(), set(), {}, set()
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
                new_links[scim_user_id] = user_id
            if user_id in in_project and user_id not in granted:
                continue   # a member before SCIM synced the project: their role stays, never removed by SCIM
            if user_id not in in_project:
                try:
                    self.platform.add_member(project_id, user_id, DEFAULT_ROLE)
                except Exception:  # pylint: disable=W0703
                    log.exception("SCIM: adding %s to project %s failed", user_id, project_id)
                    result["errors"] += 1
                    continue
                touched.add(user_id)
                result["added"] += 1
                self._audit("SCIM_MEMBER_ADDED", f"user:{user_id};role:{DEFAULT_ROLE}", project_id=project_id)
            if user_id not in granted:
                new_grants.add(user_id)
        removed = set()
        for user_id in granted - keep:
            try:
                self.platform.remove_member(project_id, user_id)
            except Exception:  # pylint: disable=W0703
                log.exception("SCIM: removing %s from project %s failed", user_id, project_id)
                result["errors"] += 1
                continue
            removed.add(user_id)
            touched.add(user_id)
            result["removed"] += 1
            self._audit("SCIM_MEMBER_REMOVED", f"user:{user_id}", project_id=project_id)
        self._store_membership(project_id, group_id, new_links, new_grants, removed)
        if touched:
            try:
                self.platform.clear_user_projects_cache(sorted(touched))
            except Exception:  # pylint: disable=W0703
                log.warning("SCIM: project caches of %s were not cleared", sorted(touched))

    def _store_membership(self, project_id, group_id, new_links, new_grants, removed):
        """ One short transaction per project for what the platform calls changed """
        if not (new_links or new_grants or removed):
            return
        with self.get_session() as session:
            for scim_user_id, user_id in new_links.items():
                session.query(ScimUser).filter(ScimUser.id == scim_user_id, ScimUser.elitea_user_id.is_(None)).update(
                    {ScimUser.elitea_user_id: user_id}, synchronize_session=False)
            for user_id in new_grants:
                session.add(ScimMembershipGrant(project_id=project_id, user_id=user_id, group_id=group_id,
                                                granted_at=_now()))
            if removed:
                session.query(ScimMembershipGrant).filter(
                    ScimMembershipGrant.project_id == project_id, ScimMembershipGrant.group_id == group_id,
                    ScimMembershipGrant.user_id.in_(removed)).delete(synchronize_session=False)
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
