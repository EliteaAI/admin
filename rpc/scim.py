""" SCIM provisioning RPCs (#5202) """
from pylon.core.tools import web  # pylint: disable=E0401


class RPC:  # pylint: disable=R0903
    @web.rpc("admin_scim_is_protected")
    def admin_scim_is_protected(self, project_id: int) -> bool:
        """ Whether a project is managed by SCIM (only member roles may then be changed) """
        scim = getattr(self, "scim", None)
        return bool(scim is not None and scim.guards.is_protected(int(project_id)))

    @web.rpc("admin_scim_protected_ids")
    def admin_scim_protected_ids(self) -> list:
        scim = getattr(self, "scim", None)
        return sorted(scim.guards.protected_ids()) if scim is not None else []

    @web.rpc("admin_scim_sync")
    def admin_scim_sync(self, **kwargs) -> bool:
        """ Scheduled: read group nesting from Graph and sync SCIM projects """
        scim = getattr(self, "scim", None)
        if scim is None:
            return False
        scim.request_sync(graph_pull=True)
        return True
