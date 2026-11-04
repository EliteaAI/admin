""" SCIM provisioning events (#5202) """
from pylon.core.tools import web  # pylint: disable=E0401


class Event:  # pylint: disable=R0903
    @web.event("admin_scim_projects_changed")
    def _scim_projects_changed(self, context, event, payload):  # pylint: disable=W0613
        """ A replica created or suspended a SCIM project: drop this replica's cached protected set """
        scim = getattr(self, "scim", None)
        if scim is not None:
            scim.on_projects_changed_event()
