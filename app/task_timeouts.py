"""Per-task deadlines.

Every task has two deadlines, both computed here from its kind and params:

  * ``agent`` - sent to the agent as ``AgentRequest.timeout_seconds``. The agent
    kills the job's worker after this long and gives its handler slightly less.
    ``None`` lets the agent fall back to its own per-kind defaults.
  * ``backend`` - when the timeout sweeper flips the task to ``timeout`` and frees
    its VM lock. It is ``agent + _AGENT_GRACE_SECONDS`` so the backend never gives
    up while the agent is still working (the backend counts from ``created_at``,
    which includes the time the job waited in the agent's queue).

Disk work scales with size, so these kinds add a budget on top of their base:

  * ``vm_create`` / ``vm_edit`` - from the params: a Fixed VHD is zero-filled when
    it is created or expanded.
  * ``vm_move`` / ``vm_rename`` (``Move-VMStorage``), ``vm_export_template``
    (``Export-VM``, then Fixed disks converted to Dynamic) and ``vm_clone`` - from
    the disks the operation copies (``disks``, the VM's or the template's).

The default (``OVC_TASK_TIMEOUT_SECONDS``) suits quick agent operations.

Used by:
  * the task builders (``app.services.vms`` / ``host_actions`` / ``agent_upgrade``)
  * ``app.worker.main._sweep_stale_tasks`` - ``Task.timeout_seconds``, else
    ``task_timeout_seconds(kind)``
  * ``app.cache`` - the VM-lock TTL (crash backstop)
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, NamedTuple

from .config import get_settings

# Agent-side budget for kinds that legitimately run for minutes (a graceful guest
# shutdown, a storage migration, disk creation).
_AGENT_BASE_TIMEOUTS: dict[str, int] = {
    "vm_shutdown": 600,
    "vm_create": 1800,
    "vm_move": 1800,
    "vm_rename": 1800,
    "vm_export_template": 1800,
    "vm_batch_start": 1800,
    "vm_batch_stop": 1800,
    "vm_clone": 1800,
    "vm_edit": 1800,
}

# Backend-only deadlines for kinds whose agent-side lifetime the agent manages
# itself (the upgrade swaps the agent process mid-task).
_BACKEND_TIMEOUTS: dict[str, int] = {
    # download of a ~12-40 MiB binary + checksum + drain + service swap + the
    # NEW agent starting and publishing the terminal response. The old agent
    # goes quiet at 99% during the swap, so keep the window generous.
    "host_update_agent": 1800,
}

_AGENT_GRACE_SECONDS = 300

# Fixed VHDs are zero-filled: ~100 MB/s, conservative for SAN/CSV storage.
_FIXED_DISK_SECONDS_PER_GB = 10
_FIXED_DISK_MIN_SECONDS = 120
# Dynamic VHDs only write metadata.
_DYNAMIC_DISK_SECONDS = 60
# Copying VHD data (Move-VMStorage, Export-VM, Import-VM -Copy, Convert-VHD): same
# conservative ~100 MB/s.
_COPY_SECONDS_PER_GB = 10

_GIB = 1024**3


class DiskSize(NamedTuple):
    """A disk an operation copies: provisioned size, bytes used on storage."""

    size_bytes: int
    used_bytes: int
    fixed: bool


class TaskTimeouts(NamedTuple):
    agent: int | None
    backend: int


def disk_timeout_seconds(size_gb: float, fixed: bool) -> int:
    """Time to create or expand one VHD of ``size_gb``."""
    if not fixed:
        return _DYNAMIC_DISK_SECONDS
    return max(int(size_gb * _FIXED_DISK_SECONDS_PER_GB), _FIXED_DISK_MIN_SECONDS)


def _disk_list(value: Any) -> list[dict[str, Any]]:
    # vm_edit accepts a single disk object or a list of them
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [d for d in value if isinstance(d, dict)]
    return []


def _copy_seconds(nbytes: int) -> int:
    return nbytes * _COPY_SECONDS_PER_GB // _GIB


def _copy_budget_seconds(
    kind: str, params: dict[str, Any], disks: Sequence[DiskSize]
) -> int:
    used = sum(d.used_bytes for d in disks)
    if kind in ("vm_move", "vm_rename"):
        return _copy_seconds(used)
    if kind == "vm_export_template":
        # Export-VM copies the data, then each Fixed disk is converted to Dynamic
        # (reads the full disk again)
        return _copy_seconds(used) + _copy_seconds(
            sum(d.size_bytes for d in disks if d.fixed)
        )
    if kind == "vm_clone":
        if params.get("clone_type") == "imported":
            # Export-VM of the source, then Import-VM -Copy of the export
            return 2 * _copy_seconds(used)
        # Import-VM -Copy of the template, then (by default) its Dynamic disks are
        # converted to Fixed - a full zero-filled write
        total = _copy_seconds(used)
        if params.get("expand_disks") is not False:
            total += sum(
                disk_timeout_seconds(d.size_bytes / _GIB, True)
                for d in disks
                if not d.fixed
            )
        return total
    return 0


def _disk_budget_seconds(kind: str, params: dict[str, Any]) -> int:
    def size(d: dict[str, Any]) -> float:
        try:
            return float(d.get("size_gb") or 0)
        except (TypeError, ValueError):
            return 0

    if kind == "vm_create":
        created = _disk_list(params.get("disks"))
        expanded: list[dict[str, Any]] = []
    elif kind == "vm_edit":
        created = _disk_list(params.get("add_disk"))
        expanded = _disk_list(params.get("edit_disk"))
    else:
        return 0
    total = sum(disk_timeout_seconds(size(d), d.get("type") == "Fixed") for d in created)
    # edit_disk does not say whether the disk is Fixed; assume it is (expanding a
    # Fixed disk zero-fills the new space)
    total += sum(disk_timeout_seconds(size(d), True) for d in expanded)
    return total


def task_timeouts(
    kind: str,
    params: dict[str, Any] | None = None,
    *,
    disks: Sequence[DiskSize] = (),
) -> TaskTimeouts:
    """The agent and backend deadlines for a task of ``kind`` with ``params``;
    ``disks`` are the ones a copying operation moves (see the module docstring)."""
    default = get_settings().task_timeout_seconds
    base = _AGENT_BASE_TIMEOUTS.get(kind)
    params = params or {}
    extra = _disk_budget_seconds(kind, params) + _copy_budget_seconds(
        kind, params, disks
    )
    if base is None and not extra:
        return TaskTimeouts(None, max(_BACKEND_TIMEOUTS.get(kind, 0), default))
    agent = (base or default) + extra
    return TaskTimeouts(agent, max(agent + _AGENT_GRACE_SECONDS, default))


def task_timeout_seconds(kind: str | None) -> int:
    """The backend deadline for a task of this ``kind`` when its params are not
    known (no stored ``Task.timeout_seconds``)."""
    return task_timeouts(kind or "").backend
