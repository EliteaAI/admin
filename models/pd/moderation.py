from pydantic import BaseModel, Field, field_validator
from typing import Optional, Dict, Any

from enum import Enum


class ModerationStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class ModerationStateCreate(BaseModel):
    issue_type: str = Field(..., min_length=1, max_length=256)
    description: str = Field(..., min_length=1)
    status: ModerationStatus = Field(default=ModerationStatus.PENDING)
    meta: Optional[Dict[str, Any]] = Field(default_factory=dict)
    user_id: Optional[int] = None


class ModerationStateUpdate(BaseModel):
    id: int = Field(..., ge=1)
    status: Optional[ModerationStatus] = None
    rejection_comment: Optional[str] = None
    meta: Optional[Dict[str, Any]] = None
    user_id: Optional[int] = None

    @field_validator('rejection_comment')
    @classmethod
    def validate_rejection_comment(cls, v, info):
        if info.data.get('status') == ModerationStatus.REJECTED and not v:
            raise ValueError("rejection_comment is required when status is 'rejected'")
        return v


class ModerationStateResponse(BaseModel):
    id: int
    user_id: int
    project_id: int
    issue_type: str
    entity_id: Optional[int]
    description: str
    status: str
    rejection_comment: Optional[str]
    meta: Optional[Dict[str, Any]]
    created_at: str
    updated_at: Optional[str] = None


class ModerationStateListResponse(BaseModel):
    total: int
    rows: list[ModerationStateResponse]


class ModerationStateListQuery(BaseModel):
    limit: int = Field(default=20, ge=1, le=100)
    offset: int = Field(default=0, ge=0)
    search: Optional[str] = None
    status: Optional[ModerationStatus] = None
    issue_type: Optional[str] = None
    project_id: Optional[int] = Field(None, ge=1)
    entity_id: Optional[int] = Field(None, ge=1)
    sort_by: str = Field(default="created_at", max_length=64)
    sort_order: str = Field(default="desc", pattern="^(asc|desc)$")
