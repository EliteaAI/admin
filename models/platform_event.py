"""Platform event log model - simple event logging for pylon lifecycle."""

from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy import Integer, String, DateTime, func

from tools import db, config as c


class PlatformEvent(db.Base):
    __tablename__ = 'platform_event'
    __table_args__ = (
        {'schema': c.POSTGRES_SCHEMA},
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    pylon_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    user_id: Mapped[int] = mapped_column(Integer, nullable=True)
    meta: Mapped[dict] = mapped_column(JSONB, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "pylon_id": self.pylon_id,
            "event_type": self.event_type,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "user_id": self.user_id,
            "meta": self.meta,
        }
