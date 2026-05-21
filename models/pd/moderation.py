from pydantic import BaseModel, Field, field_validator
from typing import Optional, Dict, Any
from datetime import datetime


class ModerationStateCreate(BaseModel):
    issue_type: str = Field(..., min_length=1, max_length=256)
    project_id: int = Field(..., ge=1)
    entity_id: Optional[int] = Field(None, ge=1)
    description: str = Field(..., min_length=1)
    status: str = Field(default="pending", max_length=64)
    meta: Optional[Dict[str, Any]] = Field(default_factory=dict)

    @field_validator('status')
    @classmethod
    def validate_status(cls, v):
        allowed_statuses = ['pending', 'approved', 'rejected']
        if v not in allowed_statuses:
            raise ValueError(f'Status must be one of: {", ".join(allowed_statuses)}')
        return v


class ModerationStateUpdate(BaseModel):
    id: int = Field(..., ge=1)
    status: Optional[str] = Field(None, max_length=64)
    rejection_comment: Optional[str] = None
    meta: Optional[Dict[str, Any]] = None

    @field_validator('status')
    @classmethod
    def validate_status(cls, v):
        if v is not None:
            allowed_statuses = ['pending', 'approved', 'rejected']
            if v not in allowed_statuses:
                raise ValueError(f'Status must be one of: {", ".join(allowed_statuses)}')
        return v

    @field_validator('rejection_comment')
    @classmethod
    def validate_rejection_comment(cls, v, info):
        if info.data.get('status') == 'rejected' and not v:
            raise ValueError('rejection_comment is required when status is rejected')
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
    updated_at: str


class ModerationStateListResponse(BaseModel):
    total: int
    rows: list[ModerationStateResponse]


class ModerationStateListQuery(BaseModel):
    limit: int = Field(default=20, ge=1, le=100)
    offset: int = Field(default=0, ge=0)
    search: Optional[str] = None
    status: Optional[str] = None
    issue_type: Optional[str] = None
    project_id: Optional[int] = Field(None, ge=1)
    entity_id: Optional[int] = Field(None, ge=1)
    sort_by: str = Field(default="created_at", max_length=64)
    sort_order: str = Field(default="desc", pattern="^(asc|desc)$")

    @field_validator('status')
    @classmethod
    def validate_status(cls, v):
        if v is not None:
            allowed_statuses = ['pending', 'approved', 'rejected']
            if v not in allowed_statuses:
                raise ValueError(f'Status must be one of: {", ".join(allowed_statuses)}')
        return v
