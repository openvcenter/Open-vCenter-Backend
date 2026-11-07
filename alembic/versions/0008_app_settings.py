"""app settings

Adds `app_settings`: one row (id 1) of application-wide preferences - metrics
retention and the VM console access flag for non-administrators.

Revision ID: 0008_app_settings
Revises: 0007_task_timeout
Create Date: 2026-11-07 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0008_app_settings"
down_revision: str | None = "0007_task_timeout"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "app_settings",
        sa.Column("id", sa.Integer(), autoincrement=False, nullable=False),
        sa.Column(
            "metrics_retention_seconds",
            sa.Integer(),
            server_default=sa.text("3600"),
            nullable=False,
        ),
        sa.Column(
            "vm_console_non_admin_access",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_app_settings")),
    )
    op.execute("INSERT INTO app_settings (id) VALUES (1)")


def downgrade() -> None:
    op.drop_table("app_settings")
