"""Platform status service - ORM operations for lifecycle tracking."""

import re
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Tuple

from sqlalchemy import and_
from sqlalchemy.orm import Session

from pylon.core.tools import log

from ..models.platform_status import PlatformStatus


# Pattern to strip UUID suffix from pylon_id
# e.g. "pylon-indexer_a0c0048f-61c3-4c94-acde-99036172ca48" -> "pylon-indexer"
_PYLON_ID_PATTERN = re.compile(r'^(pylon-[a-z]+)(?:_[a-f0-9-]+)?$', re.IGNORECASE)


def normalize_pylon_id(pylon_id: str) -> str:
    """
    Normalize pylon_id by stripping the UUID suffix.

    The pylon_id includes a UUID that changes on restart, making it
    impossible to match the flag record with the restarted pylon.
    """
    match = _PYLON_ID_PATTERN.match(pylon_id)
    if match:
        return match.group(1).lower()
    return pylon_id


class PlatformStatusService:
    """Service for platform status lifecycle operations."""

    # Track which pylons have been processed this session
    # Prevents creating multiple "unplanned" records on repeated heartbeats
    _processed_pylons: set = set()

    @classmethod
    def reset_processed(cls):
        """Reset processed pylons tracking (for testing)."""
        cls._processed_pylons.clear()

    @staticmethod
    def create_planned_event(
        session: Session,
        pylon_id: str,
        event_type: str,
        user_id: Optional[int] = None,
        metadata: Optional[dict] = None,
        set_start_time: bool = False,
    ) -> PlatformStatus:
        """Create a new planned lifecycle event (flag record)."""
        normalized_id = normalize_pylon_id(pylon_id)
        now = datetime.now(timezone.utc)
        event = PlatformStatus(
            pylon_id=normalized_id,
            event_type=event_type,
            trigger='ui',
            initiated_at=now,
            start_time=now if set_start_time else None,
            initiated_by_user_id=user_id,
            metadata_=metadata,
        )
        session.add(event)
        session.flush()
        log.info("Created %s event %d for pylon %s", event_type, event.id, normalized_id)
        return event

    @staticmethod
    def set_start_time(session: Session, pylon_id: str) -> List[int]:
        """Set start_time for open events when shutdown begins."""
        normalized_id = normalize_pylon_id(pylon_id)
        now = datetime.now(timezone.utc)

        open_events = session.query(PlatformStatus).filter(
            and_(
                PlatformStatus.pylon_id == normalized_id,
                PlatformStatus.end_time.is_(None),
                PlatformStatus.start_time.is_(None),
            )
        ).all()

        updated_ids = []
        for event in open_events:
            event.start_time = now
            updated_ids.append(event.id)

        if updated_ids:
            log.info("Set start_time for events: %s", updated_ids)

        return updated_ids

    @classmethod
    def complete_open_events(cls, session: Session, pylon_id: str) -> List[int]:
        """Complete all open events for a pylon (on startup)."""
        normalized_id = normalize_pylon_id(pylon_id)
        now = datetime.now(timezone.utc)

        open_events = session.query(PlatformStatus).filter(
            and_(
                PlatformStatus.pylon_id == normalized_id,
                PlatformStatus.end_time.is_(None),
            )
        ).all()

        completed_ids = []
        for event in open_events:
            event.end_time = now
            completed_ids.append(event.id)

        if completed_ids:
            log.info("Completed events: %s", completed_ids)
            # Mark as processed so we don't create unplanned later
            cls._processed_pylons.add(normalized_id)

        return completed_ids

    @classmethod
    def create_unplanned_event(cls, session: Session, pylon_id: str) -> Optional[PlatformStatus]:
        """Create an unplanned restart record (only once per pylon startup)."""
        normalized_id = normalize_pylon_id(pylon_id)

        # Check if already processed this startup
        if normalized_id in cls._processed_pylons:
            return None

        event = PlatformStatus(
            pylon_id=normalized_id,
            event_type='restart',
            trigger='unplanned',
            end_time=datetime.now(timezone.utc),
        )
        session.add(event)
        session.flush()
        log.info("Created unplanned restart event %d for %s", event.id, normalized_id)

        # Mark as processed
        cls._processed_pylons.add(normalized_id)

        return event

    @staticmethod
    def has_recent_completion(session: Session, pylon_id: str, seconds: int = 60) -> bool:
        """Check if pylon has a recently completed event."""
        normalized_id = normalize_pylon_id(pylon_id)
        threshold = datetime.now(timezone.utc) - timedelta(seconds=seconds)

        return session.query(PlatformStatus).filter(
            and_(
                PlatformStatus.pylon_id == normalized_id,
                PlatformStatus.end_time > threshold,
            )
        ).first() is not None

    @staticmethod
    def list_events(
        session: Session,
        pylon_id: Optional[str] = None,
        event_type: Optional[str] = None,
        trigger: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[PlatformStatus], int]:
        """List events with filtering and pagination."""
        query = session.query(PlatformStatus)

        if pylon_id:
            query = query.filter(PlatformStatus.pylon_id == pylon_id)
        if event_type:
            query = query.filter(PlatformStatus.event_type == event_type)
        if trigger:
            query = query.filter(PlatformStatus.trigger == trigger)

        total = query.count()

        rows = query.order_by(
            PlatformStatus.initiated_at.desc().nulls_last()
        ).limit(limit).offset(offset).all()

        return rows, total
