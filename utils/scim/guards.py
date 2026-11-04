""" Protection of SCIM-managed projects (#5202): only member roles may be changed by people """
import time


CACHE_TTL_S = 10   # fallback: changes are also announced to every replica (admin_scim_projects_changed)
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
        from sqlalchemy import select  # pylint: disable=C0415
        from ...models.scim import ScimProject  # pylint: disable=C0415
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

    def refusal(self, project_id, allowed=None):
        """ The API's 403 while the project is managed by SCIM, else None.
            ``allowed(guards)`` -> True lets this particular change through (roles, admin grant). """
        if not self.is_protected(project_id) or (allowed is not None and allowed(self)):
            return None
        return {"error": MANAGED_MESSAGE, "scim_managed": True}, 403

    def can_set_roles(self, project_id, user_ids, roles, member_ids) -> bool:
        """ roles of existing members to a non-empty set: an empty set removes, a non-member would be added """
        if not self.is_protected(project_id):
            return True
        return bool(roles) and set(user_ids) <= set(member_ids)


class ScimManagedError(PermissionError):
    """ A change to a SCIM-managed project that people may not make """

    def __init__(self):
        super().__init__(MANAGED_MESSAGE)


def refusal(module, project_id, allowed=None):
    """ Guards.refusal of the module's SCIM runtime; None when SCIM provisioning is off """
    scim = getattr(module, "scim", None)
    return scim.guards.refusal(project_id, allowed) if scim is not None else None
