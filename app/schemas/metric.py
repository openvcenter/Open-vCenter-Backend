from __future__ import annotations

from datetime import datetime
from typing import Any

from .common import CamelModel


class HostMetricSample(CamelModel):
    ts: datetime
    cpu_percent: float | None = None
    cpu_max_percent: float | None = None
    mem_percent: float | None = None
    disk_read_bps: float | None = None
    disk_write_bps: float | None = None
    disk_read_iops: float | None = None
    disk_write_iops: float | None = None
    disk_read_latency_ms: float | None = None
    disk_write_latency_ms: float | None = None
    net_rx_bps: float | None = None
    net_tx_bps: float | None = None
    detail: dict[str, Any] | None = None


class VmMetricSample(CamelModel):
    ts: datetime
    cpu_percent: float | None = None
    cpu_max_percent: float | None = None
    mem_bytes: float | None = None
    mem_pressure: float | None = None
    disk_read_bps: float | None = None
    disk_write_bps: float | None = None
    disk_read_iops: float | None = None
    disk_write_iops: float | None = None
    disk_latency_ms: float | None = None
    net_rx_bps: float | None = None
    net_tx_bps: float | None = None
    detail: dict[str, Any] | None = None
