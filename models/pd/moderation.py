try:
    from pydantic.v1 import BaseModel, Field, validator
except:  # pylint: disable=W0702
    from pydantic import BaseModel, Field, validator

from typing import Optional, Dict, Any
from datetime import datetime


class ModerationStateCreate(BaseModel):
    issue_type: str = Field(..., min_length=1, max_length=256)
    project_id: int = Field(..., ge=1)
    entity_id: Optional[int] = Field(None, ge=1)
    description: str = Field(..., min_length=1)
    status: str = Field(default="pending", max_length=64)
    meta: Optional[Dict[str, Any]] = Field(default_factory=dict)

    @validator('status')
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

    @validator('status')
    def validate_status(cls, v):
        if v is not None:
            allowed_statuses = ['pending', 'approved', 'rejected']
            if v not in allowed_statuses:
                raise ValueError(f'Status must be one of: {", ".join(allowed_statuses)}')
        return v

    @validator('rejection_comment')
    def validate_rejection_comment(cls, v, values):
        if values.get('status') == 'rejected' and not v:
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
    sort_order: str = Field(default="desc", regex="^(asc|desc)$")

    @validator('status')
    def validate_status(cls, v):
        if v is not None:
            allowed_statuses = ['pending', 'approved', 'rejected']
            if v not in allowed_statuses:
                raise ValueError(f'Status must be one of: {", ".join(allowed_statuses)}')
        return v
