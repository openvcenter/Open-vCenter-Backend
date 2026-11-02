"""task timeout

Adds `tasks.timeout_seconds`: the task's own backend deadline, computed when it
is queued (`app.task_timeouts`) - disk work scales it with the disk sizes.

Revision ID: 0007_task_timeout
Revises: 0006_rbac
Create Date: 2026-11-02 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0007_task_timeout"
down_revision: str | None = "0006_rbac"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("tasks", sa.Column("timeout_seconds", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("tasks", "timeout_seconds")
