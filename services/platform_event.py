"""Platform event service - simple event logging operations."""

from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional, List, Tuple

from sqlalchemy.orm import Session

from pylon.core.tools import log

from ..models.platform_event import PlatformEvent


RETENTION_DAYS = 7
PRUNE_BATCH_SIZE = 500


class EventType(str, Enum):
    RESTART_REQUESTED = 'restart_requested'
    RELOAD_REQUESTED = 'reload_requested'
    PYLON_STARTED = 'pylon_started'


def extract_plugins(runtime_info: list) -> dict:
    """Extract plugin name->version mapping from runtime_info list."""
    return {
        p.get("name"): p.get("local_version", "")
        for p in runtime_info
        if p.get("name")
    }


class PlatformEventService:
    """Service for platform event logging."""

    @staticmethod
    def log_event(
        session: Session,
        pylon_id: str,
        event_type: str,
        user_id: Optional[int] = None,
        meta: Optional[dict] = None,
    ) -> PlatformEvent:
        """Log a platform event."""
        event = PlatformEvent(
            pylon_id=pylon_id,
            event_type=event_type,
            user_id=user_id,
            meta=meta,
        )
        session.add(event)
        session.flush()
        log.info("Logged platform event: %s for %s", event_type, pylon_id)
        return event

    @staticmethod
    def has_event(
        session: Session,
        pylon_id: str,
        event_type: str,
    ) -> bool:
        """Check if an event already exists for this pylon_id and type."""
        return session.query(PlatformEvent).filter(
            PlatformEvent.pylon_id == pylon_id,
            PlatformEvent.event_type == event_type,
        ).first() is not None

    @staticmethod
    def list_events(
        session: Session,
        pylon_id: Optional[str] = None,
        event_type: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[PlatformEvent], int]:
        """List events with filtering and pagination."""
        query = session.query(PlatformEvent)

        if pylon_id:
            query = query.filter(PlatformEvent.pylon_id == pylon_id)
        if event_type:
            query = query.filter(PlatformEvent.event_type == event_type)
        if since:
            query = query.filter(PlatformEvent.created_at >= since)
        if until:
            query = query.filter(PlatformEvent.created_at <= until)

        total = query.count()

        rows = query.order_by(
            PlatformEvent.created_at.desc()
        ).limit(limit).offset(offset).all()

        return rows, total

    @staticmethod
    def prune_old_events(session: Session, keep_days: int = RETENTION_DAYS) -> int:
        """Delete events older than keep_days. Returns count deleted."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=keep_days)
        total_deleted = 0

        while True:
            subq = session.query(PlatformEvent.id).filter(
                PlatformEvent.created_at < cutoff
            ).limit(PRUNE_BATCH_SIZE).subquery()

            deleted = session.query(PlatformEvent).filter(
                PlatformEvent.id.in_(session.query(subq))
            ).delete(synchronize_session=False)

            session.commit()
            total_deleted += deleted

            if deleted < PRUNE_BATCH_SIZE:
                break

        if total_deleted > 0:
            log.info("Pruned %d old platform events (older than %d days)", total_deleted, keep_days)

        return total_deleted
