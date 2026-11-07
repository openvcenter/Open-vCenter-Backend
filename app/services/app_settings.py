from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from ..api.errors import ApiError
from ..ids import new_id
from ..messaging import AgentRequest, publish_request
from ..messaging.protocol import MetricsConfigParams
from ..models import APP_SETTINGS_ID, AppSettings

log = logging.getLogger(__name__)

# Metrics retention presets offered by the Application Preferences dialog:
# 1 h, 6 h, 12 h, 24 h, 3 days, 7 days.
METRICS_RETENTION_OPTIONS: tuple[int, ...] = (3600, 21600, 43200, 86400, 259200, 604800)

# Metrics collection interval presets: 30 s, 1, 2, 5 and 10 min. The agent
# samples every 5 s and publishes one mean/peak row per interval.
METRICS_INTERVAL_OPTIONS: tuple[int, ...] = (30, 60, 120, 300, 600)
DEFAULT_METRICS_INTERVAL = 300


async def get_app_settings(db: AsyncSession) -> AppSettings:
    """The settings row, created with the defaults if migration 0008's seed is gone."""
    settings = await db.get(AppSettings, APP_SETTINGS_ID)
    if settings is None:
        settings = AppSettings(
            id=APP_SETTINGS_ID,
            metrics_retention_seconds=3600,
            metrics_interval_seconds=DEFAULT_METRICS_INTERVAL,
            vm_console_non_admin_access=False,
        )
        db.add(settings)
        await db.flush()
    return settings


async def metrics_retention_seconds(db: AsyncSession) -> int:
    return (await get_app_settings(db)).metrics_retention_seconds


def check_metrics_retention(seconds: int) -> int:
    """`seconds` when it is one of the presets, else 400 INVALID."""
    if seconds not in METRICS_RETENTION_OPTIONS:
        raise ApiError(
            "INVALID",
            "Metrics retention must be one of "
            + ", ".join(str(s) for s in METRICS_RETENTION_OPTIONS)
            + " seconds",
        )
    return seconds


async def metrics_interval_seconds(db: AsyncSession) -> int:
    return (await get_app_settings(db)).metrics_interval_seconds


def check_metrics_interval(seconds: int) -> int:
    """`seconds` when it is one of the presets, else 400 INVALID."""
    if seconds not in METRICS_INTERVAL_OPTIONS:
        raise ApiError(
            "INVALID",
            "Metrics interval must be one of "
            + ", ".join(str(s) for s in METRICS_INTERVAL_OPTIONS)
            + " seconds",
        )
    return seconds


async def send_metrics_config(host_ref: str, seconds: int) -> None:
    """Push the collection interval to one agent (set_metrics_config). No Task:
    the agent confirms through the metrics_interval of its next agent_status, and
    apply_agent_status resends on a mismatch. Best-effort - errors are logged."""
    request = AgentRequest(
        id=new_id(),
        function="set_metrics_config",
        params=MetricsConfigParams(interval_seconds=seconds).model_dump(),
        requested_by="system",
    )
    try:
        await publish_request(host_ref, request)
    except Exception:
        log.exception("set_metrics_config not sent to host=%s", host_ref)
