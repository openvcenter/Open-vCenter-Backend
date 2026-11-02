from __future__ import annotations

from sqlalchemy import JSON, Boolean, CheckConstraint, ForeignKey, Index, String, text
from sqlalchemy.orm import Mapped, mapped_column

from ..ids import new_id
from .base import UUID_STR, Base, TimestampMixin


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(UUID_STR, primary_key=True, default=new_id)
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # groups from the last sign-in (informational - access uses the live token)
    groups: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)


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
    """Grants `role` to a group on one inventory object (or globally).

    `group_id` is the group as the identity provider identifies it (OIDC: the
    name in the groups claim, see api/deps.py) - permissions never name an
    individual user. `scope_id` has no FK because
    the target table depends on `scope_type`; deleting an object deletes its
    permissions explicitly (services/rbac.py::delete_permissions).
    """

    __tablename__ = "permissions"
    __table_args__ = (
        CheckConstraint(
            "scope_type IN ('global', 'cluster', 'host', 'folder', 'vm')",
            name="scope_type",
        ),
        CheckConstraint("(scope_type = 'global') = (scope_id IS NULL)", name="scope_id"),
        # one permission per group per object
        Index(
            "uq_permissions_group_scope",
            "group_id",
            "scope_type",
            "scope_id",
            unique=True,
            postgresql_where=text("scope_id IS NOT NULL"),
        ),
        Index(
            "uq_permissions_group_global",
            "group_id",
            unique=True,
            postgresql_where=text("scope_id IS NULL"),
        ),
        Index("ix_permissions_scope", "scope_type", "scope_id"),
        Index("ix_permissions_group_id", "group_id"),
    )

    id: Mapped[str] = mapped_column(UUID_STR, primary_key=True, default=new_id)
    group_id: Mapped[str] = mapped_column(String(255), nullable=False)
    role_id: Mapped[str] = mapped_column(
        UUID_STR, ForeignKey("roles.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    scope_type: Mapped[str] = mapped_column(String(16), nullable=False)
    scope_id: Mapped[str | None] = mapped_column(UUID_STR, nullable=True)
    # false: applies to the object itself only, not to what is below it
    propagate: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
