"""Platform event handlers - log pylon lifecycle events."""

from pylon.core.tools import log, web

from tools import db

from ..services.platform_event import PlatformEventService, EventType, extract_plugins


class Event:
    """Platform event handlers."""

    @web.event("bootstrap_runtime_info")
    def _on_pylon_started(self, context, event, payload):
        """Log when a pylon starts (first heartbeat only per pylon instance)."""
        _ = context, event

        if not isinstance(payload, dict):
            return

        pylon_id = payload.get("pylon_id")
        if not pylon_id:
            return

        try:
            with db.get_session() as session:
                if PlatformEventService.has_event(session, pylon_id, EventType.PYLON_STARTED):
                    return

                plugins = extract_plugins(payload.get("runtime_info", []))

                PlatformEventService.log_event(
                    session,
                    pylon_id=pylon_id,
                    event_type=EventType.PYLON_STARTED,
                    meta={"plugins": plugins},
                )
                session.commit()

                # Prune old events on pylon startup (runs once per pylon instance)
                PlatformEventService.prune_old_events(session)
        except Exception as e:
            log.warning("Failed to log pylon_started event: %s", e)
