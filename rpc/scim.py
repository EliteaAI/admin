""" SCIM provisioning RPCs (#5202) """
from pylon.core.tools import web  # pylint: disable=E0401


class RPC:  # pylint: disable=R0903
    @web.rpc("admin_scim_sync")
    def admin_scim_sync(self, **kwargs) -> bool:
        """ Scheduled: read group nesting from Graph and re-check every SCIM project """
        scim = getattr(self, "scim", None)
        if scim is None:
            return False
        scim.request_sync(graph_pull=True, full=True)
        return True
