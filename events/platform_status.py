"""Platform status event handlers for lifecycle tracking."""

from pylon.core.tools import log, web

from tools import db

from ..services.platform_status import PlatformStatusService


class Event:
    """Platform status lifecycle event handlers."""

    @web.event("pylon_stopping")
    def _pylon_stopping(self, context, event, payload):
        """Set start_time when pylon begins shutdown."""
        _ = context, event

        log.info("Received pylon_stopping event: %s", payload)

        if not isinstance(payload, dict):
            return

        pylon_id = payload.get("pylon_id")
        if not pylon_id:
            return

        try:
            with db.get_session() as session:
                updated = PlatformStatusService.set_start_time(session, pylon_id)
                session.commit()
                log.info("Set start_time result: %s", updated)
        except Exception as e:
            log.warning("Failed to set lifecycle start_time: %s", e)

    @web.event("bootstrap_runtime_info")
    def _on_pylon_heartbeat_lifecycle(self, context, event, payload):
        """Complete lifecycle on pylon startup or create unplanned record."""
        _ = context, event

        if not isinstance(payload, dict):
            return

        pylon_id = payload.get("pylon_id")
        if not pylon_id:
            return

        try:
            with db.get_session() as session:
                completed = PlatformStatusService.complete_open_events(session, pylon_id)

                if not completed:
                    if not PlatformStatusService.has_recent_completion(session, pylon_id):
                        PlatformStatusService.create_unplanned_event(session, pylon_id)

                session.commit()
        except Exception as e:
            log.warning("Failed to process lifecycle heartbeat: %s", e)
