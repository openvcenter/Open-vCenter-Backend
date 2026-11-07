from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Float, ForeignKey, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .base import UUID_STR, Base

# Quick metrics are a short rolling time-series: the agent samples its PDH
# counters every 5 s and publishes one mean/peak row per collection interval
# (app_settings.metrics_interval_seconds); the worker keeps only the retention
# window from app_settings (see app.services.inventory and
# app.worker.main::_metrics_retention_sweeper). Rates are per second.
# Not a monitoring stack.


class HostMetric(Base):
    __tablename__ = "host_metrics"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    host_id: Mapped[str] = mapped_column(
        UUID_STR, ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # end of the agent's collection window (falls back to ingest time)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )

    cpu_percent: Mapped[float | None] = mapped_column(Float, nullable=True)
    cpu_max_percent: Mapped[float | None] = mapped_column(Float, nullable=True)
    mem_percent: Mapped[float | None] = mapped_column(Float, nullable=True)
    disk_read_bps: Mapped[float | None] = mapped_column(Float, nullable=True)
    disk_write_bps: Mapped[float | None] = mapped_column(Float, nullable=True)
    disk_read_iops: Mapped[float | None] = mapped_column(Float, nullable=True)
    disk_write_iops: Mapped[float | None] = mapped_column(Float, nullable=True)
    disk_read_latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    disk_write_latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    net_rx_bps: Mapped[float | None] = mapped_column(Float, nullable=True)
    net_tx_bps: Mapped[float | None] = mapped_column(Float, nullable=True)

    # full payload - memory bytes, peak disk latency, per-disk / per-nic breakdown
    detail: Mapped[dict | None] = mapped_column(JSONB, nullable=True)


class VmMetric(Base):
    __tablename__ = "vm_metrics"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    vm_id: Mapped[str] = mapped_column(
        UUID_STR, ForeignKey("vms.id", ondelete="CASCADE"), nullable=False, index=True
    )
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )

    cpu_percent: Mapped[float | None] = mapped_column(Float, nullable=True)
    cpu_max_percent: Mapped[float | None] = mapped_column(Float, nullable=True)
    mem_bytes: Mapped[float | None] = mapped_column(Float, nullable=True)
    # Dynamic Memory average pressure (%), null for VMs without it
    mem_pressure: Mapped[float | None] = mapped_column(Float, nullable=True)
    disk_read_bps: Mapped[float | None] = mapped_column(Float, nullable=True)
    disk_write_bps: Mapped[float | None] = mapped_column(Float, nullable=True)
    disk_read_iops: Mapped[float | None] = mapped_column(Float, nullable=True)
    disk_write_iops: Mapped[float | None] = mapped_column(Float, nullable=True)
    disk_latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    net_rx_bps: Mapped[float | None] = mapped_column(Float, nullable=True)
    net_tx_bps: Mapped[float | None] = mapped_column(Float, nullable=True)

    # full item - per-virtual-disk breakdown
    detail: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
