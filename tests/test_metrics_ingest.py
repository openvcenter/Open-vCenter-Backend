"""agent_status interval reconciliation and host/vm metrics ingestion: no DB -
a fake session holds the rows."""

from __future__ import annotations

import pytest

from app.models import APP_SETTINGS_ID, AppSettings, Host, HostMetric, VmMetric
from app.services import inventory


class _Rows:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class _Row:
    def __init__(self, id: str, vm_uuid: str):
        self.id = id
        self.vm_uuid = vm_uuid


class FakeSession:
    def __init__(self) -> None:
        self.host = Host(id="host-1", short_id="h1", name="hv01")
        self.settings = AppSettings(
            id=APP_SETTINGS_ID,
            metrics_retention_seconds=3600,
            metrics_interval_seconds=60,
            vm_console_non_admin_access=False,
        )
        self.vm_rows = [_Row("vm-1", "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA")]
        self.added: list[object] = []

    async def get(self, model, oid):
        if model is Host:
            return self.host
        if model is AppSettings:
            return self.settings
        return None

    def add(self, obj) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        pass

    async def execute(self, stmt):
        return _Rows(self.vm_rows)


@pytest.fixture
def sent(monkeypatch) -> list[tuple[str, int]]:
    calls: list[tuple[str, int]] = []

    async def fake_send(host_ref: str, seconds: int) -> None:
        calls.append((host_ref, seconds))

    monkeypatch.setattr(inventory, "send_metrics_config", fake_send)
    return calls


def _status(**extra) -> dict:
    return {"version": "1.0.9", "vm_refresh_interval": 180, "host_refresh_interval": 600} | extra


async def test_agent_status_with_another_interval_gets_the_setting(sent) -> None:
    await inventory.apply_agent_status(FakeSession(), "host-1", _status(metrics_interval=300))
    assert sent == [("h1", 60)]


async def test_agent_status_with_the_same_interval_sends_nothing(sent) -> None:
    await inventory.apply_agent_status(FakeSession(), "host-1", _status(metrics_interval=60))
    assert sent == []


async def test_agent_status_without_an_interval_sends_nothing(sent) -> None:
    await inventory.apply_agent_status(FakeSession(), "host-1", _status())
    assert sent == []


async def test_host_metrics_maps_the_window_fields() -> None:
    db = FakeSession()
    payload = {
        "reported_at": "2026-11-07T10:00:00Z",
        "cpuPercent": 12.5,
        "cpuMaxPercent": 40.0,
        "memPercent": 60.0,
        "diskReadBps": 1048576.0,
        "diskWriteBps": 2097152.0,
        "diskReadIops": 100.0,
        "diskWriteIops": 50.0,
        "diskReadLatencyMs": 1.5,
        "diskWriteLatencyMs": 3.25,
        "netRxBps": 1000.0,
        "netTxBps": 500.0,
        "disks": [{"name": "0 C:", "readBps": 1048576.0}],
    }
    await inventory.apply_host_metrics(db, "host-1", payload)
    [row] = [o for o in db.added if isinstance(o, HostMetric)]
    assert row.cpu_max_percent == 40.0
    assert row.disk_read_bps == 1048576.0
    assert row.disk_write_iops == 50.0
    assert row.disk_write_latency_ms == 3.25
    assert row.net_tx_bps == 500.0
    assert row.detail["disks"][0]["name"] == "0 C:"


async def test_vm_metrics_stores_every_known_vm() -> None:
    db = FakeSession()
    payload = {
        "reported_at": "2026-11-07T10:00:00Z",
        "vms": [
            {
                "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "cpuPercent": 20.0,
                "memBytes": 4294967296.0,
                "memPressure": 80.0,
                "diskReadBps": 300.0,
                "diskLatencyMs": 2.0,
                "netRxBps": 10.0,
            },
            {"id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "cpuPercent": 1.0},
        ],
    }
    await inventory.apply_vm_metrics(db, "host-1", payload)
    [row] = [o for o in db.added if isinstance(o, VmMetric)]
    assert row.vm_id == "vm-1"
    assert row.mem_bytes == 4294967296.0
    assert row.mem_pressure == 80.0
    assert row.disk_read_bps == 300.0
    assert row.disk_latency_ms == 2.0
    assert row.net_rx_bps == 10.0
