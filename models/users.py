from sqlalchemy import Integer, String, UniqueConstraint, ForeignKey

from tools import db_tools, db, config as c

from sqlalchemy.orm import relationship, Mapped, mapped_column


class Role(db.Base):
    __tablename__ = 'role'
    __table_args__ = (
        {'schema': c.POSTGRES_TENANT_SCHEMA},
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String, unique=True, nullable=False)

    permissions = relationship(
        'RolePermission',
        lazy='dynamic',
        uselist=True
    )
    users = relationship(
        'UserRole',
        lazy=True,
        uselist=True
    )


class RolePermission(db.Base):
    __tablename__ = 'role_permission'
    __table_args__ = (
        UniqueConstraint('role_id', 'permission', name='_role_permission_uc'),
        {'schema': c.POSTGRES_TENANT_SCHEMA},
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    role_id: Mapped[int] = mapped_column(ForeignKey(
        f'{c.POSTGRES_TENANT_SCHEMA}.{Role.__tablename__}.id'
    ), nullable=False, index=True)
    permission = mapped_column(String(128), nullable=False)


class UserRole(db.Base):
    __tablename__ = 'user_role'
    __table_args__ = (
        UniqueConstraint('user_id', 'role_id', name='_user_role_uc'),
        {"schema": c.POSTGRES_TENANT_SCHEMA},
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    role_id: Mapped[int] = mapped_column(ForeignKey(
        f'{c.POSTGRES_TENANT_SCHEMA}.{Role.__tablename__}.id'
    ), nullable=False, index=True)
