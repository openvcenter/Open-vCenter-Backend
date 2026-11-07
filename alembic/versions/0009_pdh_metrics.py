"""pdh metrics

The agent now samples PDH counters for every running VM (no Hyper-V resource
metering): new host/VM metric columns with disk throughput, IOPS and latency, a
metrics collection interval in app_settings, and no per-VM metering flag. Old
metric rows are dropped - their columns meant something else and retention is
at most 7 days.

Revision ID: 0009_pdh_metrics
Revises: 0008_app_settings
Create Date: 2026-11-07 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0009_pdh_metrics"
down_revision: str | None = "0008_app_settings"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_HOST_NEW = (
    "cpu_max_percent",
    "disk_read_bps",
    "disk_write_bps",
    "disk_read_iops",
    "disk_write_iops",
    "disk_read_latency_ms",
    "disk_write_latency_ms",
)
_VM_NEW = (
    "cpu_max_percent",
    "mem_pressure",
    "disk_read_bps",
    "disk_write_bps",
    "disk_read_iops",
    "disk_write_iops",
    "disk_latency_ms",
    "net_rx_bps",
    "net_tx_bps",
)


def upgrade() -> None:
    op.execute("DELETE FROM host_metrics")
    op.execute("DELETE FROM vm_metrics")

    op.drop_column("host_metrics", "disk_latency_ms")
    for name in _HOST_NEW:
        op.add_column("host_metrics", sa.Column(name, sa.Float(), nullable=True))
    for name in ("net_rx_bps", "net_tx_bps"):
        op.alter_column("host_metrics", name, type_=sa.Float(), existing_nullable=True)

    for name in ("disk_bytes", "net_rx_bytes", "net_tx_bytes"):
        op.drop_column("vm_metrics", name)
    op.alter_column("vm_metrics", "mem_bytes", type_=sa.Float(), existing_nullable=True)
    for name in _VM_NEW:
        op.add_column("vm_metrics", sa.Column(name, sa.Float(), nullable=True))

    op.drop_column("vms", "metrics_enabled")

    op.add_column(
        "app_settings",
        sa.Column(
            "metrics_interval_seconds",
            sa.Integer(),
            server_default=sa.text("300"),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_column("app_settings", "metrics_interval_seconds")
    op.add_column(
        "vms",
        sa.Column("metrics_enabled", sa.Boolean(), server_default=sa.text("false"), nullable=False),
    )

    op.execute("DELETE FROM host_metrics")
    op.execute("DELETE FROM vm_metrics")

    for name in _VM_NEW:
        op.drop_column("vm_metrics", name)
    op.alter_column("vm_metrics", "mem_bytes", type_=sa.BigInteger(), existing_nullable=True)
    for name in ("disk_bytes", "net_rx_bytes", "net_tx_bytes"):
        op.add_column("vm_metrics", sa.Column(name, sa.BigInteger(), nullable=True))

    for name in ("net_rx_bps", "net_tx_bps"):
        op.alter_column("host_metrics", name, type_=sa.BigInteger(), existing_nullable=True)
    for name in _HOST_NEW:
        op.drop_column("host_metrics", name)
    op.add_column("host_metrics", sa.Column("disk_latency_ms", sa.Float(), nullable=True))
