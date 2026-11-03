""" Protection of SCIM-managed projects (#5202): only member roles may be changed by people """
import time

from sqlalchemy import select

from ...models.scim import ScimProject

CACHE_TTL_S = 30
MANAGED_MESSAGE = "This project is managed by SCIM: only member roles can be changed and admins added."
ADMIN_ROLE = "admin"


class Guards:
    def __init__(self, get_session, ttl=CACHE_TTL_S):
        self.get_session = get_session
        self.ttl = ttl
        self._cache = (0.0, frozenset())

    def protected_ids(self) -> frozenset:
        loaded_at, ids = self._cache
        if self.ttl and time.monotonic() - loaded_at < self.ttl:
            return ids
        with self.get_session() as session:
            ids = frozenset(session.scalars(select(ScimProject.project_id).where(ScimProject.protected.is_(True))))
        self._cache = (time.monotonic(), ids)
        return ids

    def invalidate(self):
        self._cache = (0.0, frozenset())

    def is_protected(self, project_id) -> bool:
        return project_id in self.protected_ids()

    def can_change_project(self, project_id) -> bool:
        """ rename, delete, suspend, restore, data delete """
        return not self.is_protected(project_id)

    def can_change_membership(self, project_id) -> bool:
        """ add or remove members """
        return not self.is_protected(project_id)

    def can_add_admin(self, project_id, roles) -> bool:
        """ ELITEA admins may add project admins (role admin only) to a SCIM project """
        return not self.is_protected(project_id) or list(roles) == [ADMIN_ROLE]

    def can_set_roles(self, project_id, user_ids, roles, member_ids) -> bool:
        """ roles of existing members to a non-empty set: an empty set removes, a non-member would be added """
        if not self.is_protected(project_id):
            return True
        return bool(roles) and set(user_ids) <= set(member_ids)


def refusal(module, project_id):
    """ (body, 403) while the project is managed by SCIM, else None; for API handlers of the admin plugin """
    scim = getattr(module, "scim", None)
    if scim is not None and scim.guards.is_protected(project_id):
        return {"error": MANAGED_MESSAGE, "scim_managed": True}, 403
    return None
