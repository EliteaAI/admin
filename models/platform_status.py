"""Platform status events model for tracking pylon lifecycle."""

from datetime import datetime
from typing import Optional

from sqlalchemy import Integer, String, DateTime, Index
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from tools import db, config as c


class PlatformStatus(db.Base):
    __tablename__ = 'platform_status'
    __table_args__ = (
        Index(
            'ix_platform_status_open',
            'pylon_id',
            postgresql_where=db.text('end_time IS NULL')
        ),
        Index('ix_platform_status_pylon_time', 'pylon_id', 'initiated_at'),
        {'schema': c.POSTGRES_SCHEMA},
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    pylon_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    trigger: Mapped[str] = mapped_column(String(32), nullable=False)

    initiated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    start_time: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    end_time: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    initiated_by_user_id: Mapped[Optional[int]] = mapped_column(Integer)

    metadata_: Mapped[Optional[dict]] = mapped_column("metadata", JSONB)

    @property
    def downtime_seconds(self) -> Optional[float]:
        """Calculate downtime if both timestamps available."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None

    @property
    def is_open(self) -> bool:
        """Check if this event is still in progress."""
        return self.end_time is None

    def to_dict(self) -> dict:
        """Serialize for API response."""
        return {
            "id": self.id,
            "pylon_id": self.pylon_id,
            "event_type": self.event_type,
            "trigger": self.trigger,
            "initiated_at": self.initiated_at.isoformat() if self.initiated_at else None,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "initiated_by_user_id": self.initiated_by_user_id,
            "metadata": self.metadata_,
            "downtime_seconds": self.downtime_seconds,
        }
