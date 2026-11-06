""" Protection of members synced from SCIM groups (#5202): a project linked to a SCIM group is a normal
project, only the members the sync added may not be removed by people (or left without roles) """
import time


CACHE_TTL_S = 10   # fallback: changes are also announced to every replica (admin_scim_projects_changed)
SYNCED_MESSAGE = "These members are synced from the identity provider: remove them from the group there."


class Guards:
    def __init__(self, get_session, ttl=CACHE_TTL_S):
        self.get_session = get_session
        self.ttl = ttl
        self._cache = (0.0, frozenset())

    def linked_ids(self) -> frozenset:
        """ ids of the projects linked to a SCIM group """
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

    def is_linked(self, project_id) -> bool:
        return project_id in self.linked_ids()

    def synced_user_ids(self, project_id) -> frozenset:
        """ ELITEA user ids the SCIM sync added to the project """
        if not self.is_linked(project_id):
            return frozenset()
        from sqlalchemy import select  # pylint: disable=C0415
        from ...models.scim import ScimMembershipGrant  # pylint: disable=C0415
        with self.get_session() as session:
            return frozenset(session.scalars(select(ScimMembershipGrant.user_id).where(
                ScimMembershipGrant.project_id == project_id)))

    def refusal(self, project_id, user_ids, roles=None):
        """ The API's 403 when a change would remove synced members, else None. ``roles`` None: the users
            are removed; a list: their roles are set to it (an empty list removes them too) """
        if roles:
            return None
        synced = sorted(set(user_ids) & self.synced_user_ids(project_id))
        if not synced:
            return None
        return {"error": SYNCED_MESSAGE, "scim_synced": synced}, 403


class ScimManagedError(PermissionError):
    """ A manual change that would remove members synced from the IdP """

    def __init__(self):
        super().__init__(SYNCED_MESSAGE)


def refusal(module, project_id, user_ids, roles=None):
    """ Guards.refusal of the module's SCIM runtime; None when SCIM provisioning is off """
    scim = getattr(module, "scim", None)
    return scim.guards.refusal(project_id, user_ids, roles) if scim is not None else None
