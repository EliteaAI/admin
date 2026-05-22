from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy import Integer, String, DateTime, Text, func

from tools import db, config as c


class ModerationState(db.Base):
    __tablename__ = 'moderation_state'
    __table_args__ = (
        {'schema': c.POSTGRES_SCHEMA},
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    project_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    issue_type: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    entity_id: Mapped[str] = mapped_column(String, nullable=True, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(64), nullable=False, server_default='pending', index=True)
    rejection_comment: Mapped[str] = mapped_column(Text, nullable=True)
    created_at: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now(), nullable=False)
    updated_at: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)
    meta: Mapped[dict] = mapped_column(JSONB, nullable=True)
