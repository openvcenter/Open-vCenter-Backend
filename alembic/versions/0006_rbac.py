"""rbac: roles, role privileges, permissions

Replaces `scope_grants` (visibility only, never assignable through the API)
with privilege-based roles granted to identity-provider groups on inventory
objects; `users.roles` becomes `users.groups`. Seeds the built-in roles (fixed ids, privileges defined in
code) and a few editable sample roles.

Revision ID: 0006_rbac
Revises: 0005_audit_events
Create Date: 2026-11-01 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0006_rbac"
down_revision: str | None = "0005_audit_events"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# (id, name, description, builtin, privileges) - frozen copy, independent of
# app.services.privileges so later catalog changes don't rewrite history.
_ROLES = (
    (
        "00000000-0000-4000-8000-000000000001",
        "Administrator",
        "Every privilege, including ones added later",
        True,
        (),
    ),
    (
        "00000000-0000-4000-8000-000000000002",
        "Read-only",
        "See the object and everything below it; change nothing",
        True,
        (),
    ),
    (
        "00000000-0000-4000-8000-000000000003",
        "No access",
        "Hide the object and what is below it",
        True,
        (),
    ),
    (
        "00000000-0000-4000-8000-000000000101",
        "VM Power User",
        "Operate VMs: power, console, checkpoints, media",
        False,
        ("vm.power", "vm.console", "vm.snapshot", "vm.media"),
    ),
    (
        "00000000-0000-4000-8000-000000000102",
        "VM Console User",
        "Open VM consoles, change nothing",
        False,
        ("vm.console",),
    ),
    (
        "00000000-0000-4000-8000-000000000103",
        "VM Administrator",
        "Full control of VMs and folders",
        False,
        (
            "vm.power",
            "vm.console",
            "vm.config",
            "vm.snapshot",
            "vm.create",
            "vm.delete",
            "vm.migrate",
            "vm.media",
            "folder.manage",
        ),
    ),
    (
        "00000000-0000-4000-8000-000000000104",
        "Host Administrator",
        "Maintain and configure hosts, migrate their VMs",
        False,
        (
            "host.maintenance",
            "host.config",
            "host.manage",
            "host.console",
            "vm.migrate",
        ),
    ),
    (
        "00000000-0000-4000-8000-000000000105",
        "Auditor",
        "Read the audit log",
        False,
        ("audit.read",),
    ),
)


def _timestamps() -> list[sa.Column]:
    return [
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    ]


def upgrade() -> None:
    op.drop_index(op.f("ix_scope_grants_user_id"), table_name="scope_grants")
    op.drop_table("scope_grants")
    op.drop_column("users", "roles")
    op.add_column("users", sa.Column("groups", sa.JSON(), nullable=True))

    roles = op.create_table(
        "roles",
        sa.Column("id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.String(length=512), nullable=True),
        sa.Column("builtin", sa.Boolean(), nullable=False),
        *_timestamps(),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_roles")),
        sa.UniqueConstraint("name", name=op.f("uq_roles_name")),
    )
    role_privileges = op.create_table(
        "role_privileges",
        sa.Column("role_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("privilege", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["roles.id"],
            name=op.f("fk_role_privileges_role_id_roles"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("role_id", "privilege", name=op.f("pk_role_privileges")),
    )
    op.create_table(
        "permissions",
        sa.Column("id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("group_id", sa.String(length=255), nullable=False),
        sa.Column("role_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("scope_type", sa.String(length=16), nullable=False),
        sa.Column("scope_id", sa.Uuid(as_uuid=False), nullable=True),
        sa.Column("propagate", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=True),
        *_timestamps(),
        sa.CheckConstraint(
            "scope_type IN ('global', 'cluster', 'host', 'folder', 'vm')",
            name=op.f("ck_permissions_scope_type"),
        ),
        sa.CheckConstraint(
            "(scope_type = 'global') = (scope_id IS NULL)",
            name=op.f("ck_permissions_scope_id"),
        ),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["roles.id"],
            name=op.f("fk_permissions_role_id_roles"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_permissions")),
    )
    op.create_index(op.f("ix_permissions_role_id"), "permissions", ["role_id"], unique=False)
    op.create_index("ix_permissions_scope", "permissions", ["scope_type", "scope_id"], unique=False)
    op.create_index("ix_permissions_group_id", "permissions", ["group_id"], unique=False)
    op.create_index(
        "uq_permissions_group_scope",
        "permissions",
        ["group_id", "scope_type", "scope_id"],
        unique=True,
        postgresql_where=sa.text("scope_id IS NOT NULL"),
    )
    op.create_index(
        "uq_permissions_group_global",
        "permissions",
        ["group_id"],
        unique=True,
        postgresql_where=sa.text("scope_id IS NULL"),
    )

    op.bulk_insert(
        roles,
        [
            {"id": rid, "name": name, "description": desc, "builtin": builtin}
            for rid, name, desc, builtin, _ in _ROLES
        ],
    )
    op.bulk_insert(
        role_privileges,
        [{"role_id": rid, "privilege": priv} for rid, _, _, _, privs in _ROLES for priv in privs],
    )


def downgrade() -> None:
    op.drop_index("uq_permissions_group_global", table_name="permissions")
    op.drop_index("uq_permissions_group_scope", table_name="permissions")
    op.drop_index("ix_permissions_group_id", table_name="permissions")
    op.drop_index("ix_permissions_scope", table_name="permissions")
    op.drop_index(op.f("ix_permissions_role_id"), table_name="permissions")
    op.drop_table("permissions")
    op.drop_table("role_privileges")
    op.drop_table("roles")
    op.drop_column("users", "groups")
    op.add_column("users", sa.Column("roles", sa.String(length=512), nullable=True))

    op.create_table(
        "scope_grants",
        sa.Column("id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("user_id", sa.Uuid(as_uuid=False), nullable=False),
        sa.Column("level", sa.String(length=16), nullable=False),
        sa.Column("scope_id", sa.Uuid(as_uuid=False), nullable=True),
        *_timestamps(),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_scope_grants_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scope_grants")),
        sa.UniqueConstraint("user_id", "level", "scope_id", name="user_level_scope"),
    )
    op.create_index(op.f("ix_scope_grants_user_id"), "scope_grants", ["user_id"], unique=False)
