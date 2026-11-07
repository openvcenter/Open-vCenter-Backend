from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field


def _now() -> str:
    return datetime.now(UTC).isoformat()


class AgentRequest(BaseModel):
    """JSON the backend writes to <hostid>.request for the agent to consume."""

    id: str  # == Task.id / AMQP correlation id
    function: str  # e.g. "vm_start", "vm_delete", "host_hwinventory"
    params: dict[str, Any] = Field(default_factory=dict)
    requested_by: str
    issued_at: str = Field(default_factory=_now)
    # how long the agent may run the job (app.task_timeouts); None = agent default
    timeout_seconds: int | None = None


class AgentResponse(BaseModel):
    """JSON the agent writes to <hostid>.response."""

    id: str  # matches AgentRequest.id
    function: str
    status: str  # "running" | "succeeded" | "failed"
    progress: int | None = None
    # human-readable step text ("Exporting VM (45%)", "Creating disk 2/3: …")
    progress_message: str | None = None
    result: dict[str, Any] | str | None = None
    error: str | None = None
    # optional: the resulting VM state so the worker can update the cache fast
    vm_id: str | None = None
    vm_state: str | None = None
    # optional: the fresh, full VM object after a VM-mutating task - the backend
    # applies it to the row immediately (apply_response). One normalized VMInfo,
    # or a {"vms": [...]} wrapper (older shape); apply_response handles both.
    vm_status: dict[str, Any] | None = None
    # optional: the freshly exported template (one template_inventory item) after
    # a successful vm_export_template - the backend registers the row immediately
    # (apply_response) instead of waiting for the next template_inventory.
    template: dict[str, Any] | None = None
    finished_at: str | None = None


# Inventory payloads (last-value queues). These mirror the frontend schema shapes.


class AgentStatusPayload(BaseModel):
    version: str
    vm_refresh_interval: int
    host_refresh_interval: int
    hypervisor: str | None = None
    agent_type: str | None = None
    hostname: str | None = None
    # agent-resolved. `fqdn` -> Host.fqdn; `ip` is the management/primary address
    # (interface owning the default route), never a vMotion/storage network.
    fqdn: str | None = None
    ip: str | None = None
    os_version: str | None = None
    uptime_seconds: int | None = None
    # metrics collection window the agent is applying (see MetricsConfigParams)
    metrics_interval: int | None = None
    reported_at: str = Field(default_factory=_now)


class VmInventoryPayload(BaseModel):
    reported_at: str = Field(default_factory=_now)
    vms: list[dict[str, Any]]


class HostInventoryPayload(BaseModel):
    reported_at: str = Field(default_factory=_now)
    hardware: dict[str, Any]
    # NB: folders are application-managed, not agent-reported.


class ImageInventoryPayload(BaseModel):
    reported_at: str = Field(default_factory=_now)
    items: list[dict[str, Any]]


# Quick-metrics payloads (short time-series queues, NOT last-value). The worker
# consumes these as raw dicts; these models just document the wire shape. The
# metric fields are camelCase on the wire (cpuPercent, diskReadBps, ...); each is
# the mean over the agent's 5 s samples in one collection window, *Max the peak.


class HostMetricsPayload(BaseModel):
    reported_at: str = Field(default_factory=_now)
    cpu_percent: float | None = None
    cpu_max_percent: float | None = None
    mem_percent: float | None = None
    mem_used_bytes: float | None = None
    mem_total_bytes: float | None = None
    disk_read_bps: float | None = None
    disk_write_bps: float | None = None
    disk_read_iops: float | None = None
    disk_write_iops: float | None = None
    disk_read_latency_ms: float | None = None
    disk_write_latency_ms: float | None = None
    disk_latency_max_ms: float | None = None
    net_rx_bps: float | None = None
    net_tx_bps: float | None = None
    # [{name, readBps, writeBps, readIops, writeIops, readLatencyMs,
    #   writeLatencyMs, queueLength, busyPercent}]
    disks: list[dict[str, Any]] = Field(default_factory=list)
    net: list[dict[str, Any]] = Field(default_factory=list)  # [{name, rxBps, txBps}]


class VmMetricsPayload(BaseModel):
    reported_at: str = Field(default_factory=_now)
    # [{id (Hyper-V GUID), name, cpuPercent, cpuMaxPercent, memBytes, memPressure,
    #   diskReadBps, diskWriteBps, diskReadIops, diskWriteIops, diskLatencyMs,
    #   netRxBps, netTxBps, disks: [{path, readBps, writeBps, readIops, writeIops,
    #   latencyMs, queueLength}]}]
    vms: list[dict[str, Any]] = Field(default_factory=list)


class MetricsConfigParams(BaseModel):
    """params of set_metrics_config: the agent's collection window. The agent
    applies it without a Task or AgentResponse and reports it back as
    `metrics_interval` in agent_status."""

    interval_seconds: int
