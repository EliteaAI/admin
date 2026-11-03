""" SCIM provisioning (#5202): users and groups pushed by an IdP; every group is a protected team project """
import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Boolean, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from tools import db, config as c  # pylint: disable=E0401

SCHEMA = {'schema': c.POSTGRES_SCHEMA}


def _uuid():
    return str(uuid.uuid4())


class ScimToken(db.Base):
    __tablename__ = 'admin_scim_token'
    __table_args__ = (SCHEMA,)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    last4: Mapped[str] = mapped_column(String(4), nullable=False)
    created_by: Mapped[int] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_used_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)


class ScimUser(db.Base):
    __tablename__ = 'admin_scim_user'
    __table_args__ = (SCHEMA,)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    external_id: Mapped[str] = mapped_column(String(256), nullable=True, index=True)
    user_name: Mapped[str] = mapped_column(String(256), nullable=False, unique=True)
    email: Mapped[str] = mapped_column(String(256), nullable=True, index=True)
    display_name: Mapped[str] = mapped_column(String(256), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    elitea_user_id: Mapped[int] = mapped_column(Integer, nullable=True)
    # set when SCIM suspended the ELITEA account (active=false / DELETE), so reactivation only undoes our own suspension
    suspended_by_scim: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    deleted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())


class ScimGroup(db.Base):
    __tablename__ = 'admin_scim_group'
    __table_args__ = (SCHEMA,)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    external_id: Mapped[str] = mapped_column(String(256), nullable=True, index=True)
    display_name: Mapped[str] = mapped_column(String(256), nullable=False, unique=True)
    project_id: Mapped[int] = mapped_column(Integer, nullable=True, unique=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default='pending')  # pending|active|removed|error
    error: Mapped[str] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
    last_activity_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)


class ScimGroupMember(db.Base):
    __tablename__ = 'admin_scim_group_member'
    __table_args__ = (SCHEMA,)

    group_id: Mapped[str] = mapped_column(
        ForeignKey(f'{c.POSTGRES_SCHEMA}.admin_scim_group.id', ondelete='CASCADE'), primary_key=True)
    user_id: Mapped[str] = mapped_column(
        ForeignKey(f'{c.POSTGRES_SCHEMA}.admin_scim_user.id', ondelete='CASCADE'), primary_key=True, index=True)


class ScimGroupEdge(db.Base):
    """ Group nesting read from the IdP (Microsoft Graph): child's members are members of the parent too """
    __tablename__ = 'admin_scim_group_edge'
    __table_args__ = (SCHEMA,)

    parent_external_id: Mapped[str] = mapped_column(String(256), primary_key=True)
    child_external_id: Mapped[str] = mapped_column(String(256), primary_key=True)


class ScimProject(db.Base):
    """ Projects SCIM owns; while protected only member roles can be changed by people """
    __tablename__ = 'admin_scim_project'
    __table_args__ = (SCHEMA,)

    project_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[str] = mapped_column(String(36), nullable=True)
    protected: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class ScimSetting(db.Base):
    """ Key/value settings of SCIM provisioning (graph OAuth app, last Graph pull state) """
    __tablename__ = 'admin_scim_setting'
    __table_args__ = (SCHEMA,)

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)


class ScimMembershipGrant(db.Base):
    """ Project membership SCIM granted (directly or through a nested group): what a sync may remove """
    __tablename__ = 'admin_scim_membership_grant'
    __table_args__ = (
        UniqueConstraint('project_id', 'user_id', 'group_id', name='_admin_scim_grant_uc'),
        SCHEMA,
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False)
    group_id: Mapped[str] = mapped_column(String(36), nullable=False)
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


TABLES = [ScimToken, ScimUser, ScimGroup, ScimGroupMember, ScimGroupEdge, ScimProject, ScimSetting,
          ScimMembershipGrant]
