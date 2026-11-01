from __future__ import annotations

from sqlalchemy import Boolean, CheckConstraint, ForeignKey, Index, String, text
from sqlalchemy.orm import Mapped, mapped_column

from ..ids import new_id
from .base import UUID_STR, Base, TimestampMixin


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(UUID_STR, primary_key=True, default=new_id)
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # comma-separated role names from the last sign-in (informational)
    roles: Mapped[str | None] = mapped_column(String(512), nullable=True)


class Role(Base, TimestampMixin):
    """A named set of privileges. Built-in roles (Administrator, Read-only, No
    access) have fixed ids and their privileges defined in code
    (services/privileges.py); custom roles list theirs in role_privileges."""

    __tablename__ = "roles"

    id: Mapped[str] = mapped_column(UUID_STR, primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column(String(512), nullable=True)
    builtin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class RolePrivilege(Base):
    __tablename__ = "role_privileges"

    role_id: Mapped[str] = mapped_column(
        UUID_STR, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True
    )
    privilege: Mapped[str] = mapped_column(String(64), primary_key=True)


class Permission(Base, TimestampMixin):
    """Grants `role` to a principal on one inventory object (or globally).

    The principal is a role or group name handed over by the identity provider
    (see api/deps.py) - never an individual user. `scope_id` has no FK because
    the target table depends on `scope_type`; deleting an object deletes its
    permissions explicitly (services/rbac.py::delete_permissions).
    """

    __tablename__ = "permissions"
    __table_args__ = (
        CheckConstraint("principal_type IN ('role', 'group')", name="principal_type"),
        CheckConstraint(
            "scope_type IN ('global', 'cluster', 'host', 'folder', 'vm')",
            name="scope_type",
        ),
        CheckConstraint("(scope_type = 'global') = (scope_id IS NULL)", name="scope_id"),
        # one permission per principal per object
        Index(
            "uq_permissions_principal_scope",
            "principal_type",
            "principal_id",
            "scope_type",
            "scope_id",
            unique=True,
            postgresql_where=text("scope_id IS NOT NULL"),
        ),
        Index(
            "uq_permissions_principal_global",
            "principal_type",
            "principal_id",
            unique=True,
            postgresql_where=text("scope_id IS NULL"),
        ),
        Index("ix_permissions_scope", "scope_type", "scope_id"),
        Index("ix_permissions_principal", "principal_type", "principal_id"),
    )

    id: Mapped[str] = mapped_column(UUID_STR, primary_key=True, default=new_id)
    principal_type: Mapped[str] = mapped_column(String(16), nullable=False)
    principal_id: Mapped[str] = mapped_column(String(255), nullable=False)
    role_id: Mapped[str] = mapped_column(
        UUID_STR, ForeignKey("roles.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    scope_type: Mapped[str] = mapped_column(String(16), nullable=False)
    scope_id: Mapped[str | None] = mapped_column(UUID_STR, nullable=True)
    # false: applies to the object itself only, not to what is below it
    propagate: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
