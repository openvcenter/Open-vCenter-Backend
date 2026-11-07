from __future__ import annotations

from fastapi import APIRouter
from sqlalchemy import select

from ...models import AppSettings, Host
from ...schemas import AppSettingsOut, AppSettingsUpdate
from ...services.app_settings import (
    METRICS_INTERVAL_OPTIONS,
    METRICS_RETENTION_OPTIONS,
    check_metrics_interval,
    check_metrics_retention,
    get_app_settings,
    send_metrics_config,
)
from ...services.audit import changes, record
from ..deps import CurrentUser, DbSession, Scope

router = APIRouter(tags=["settings"])

# Application-wide preferences. Any signed-in user reads them (the metrics panels
# show the retention window); changing them needs `settings.manage` globally.


def _out(settings: AppSettings) -> AppSettingsOut:
    return AppSettingsOut(
        metrics_retention_seconds=settings.metrics_retention_seconds,
        metrics_retention_options=list(METRICS_RETENTION_OPTIONS),
        metrics_interval_seconds=settings.metrics_interval_seconds,
        metrics_interval_options=list(METRICS_INTERVAL_OPTIONS),
        vm_console_non_admin_access=settings.vm_console_non_admin_access,
    )


def _snapshot(settings: AppSettings) -> dict:
    return {
        "metricsRetentionSeconds": settings.metrics_retention_seconds,
        "metricsIntervalSeconds": settings.metrics_interval_seconds,
        "vmConsoleNonAdminAccess": settings.vm_console_non_admin_access,
    }


@router.get("/settings", response_model=AppSettingsOut)
async def get_settings(db: DbSession, scope: Scope) -> AppSettingsOut:
    return _out(await get_app_settings(db))


@router.patch("/settings", response_model=AppSettingsOut)
async def patch_settings(
    body: AppSettingsUpdate, db: DbSession, scope: Scope, user: CurrentUser
) -> AppSettingsOut:
    scope.require("settings.manage")
    settings = await get_app_settings(db)
    before = _snapshot(settings)
    if body.metrics_retention_seconds is not None:
        settings.metrics_retention_seconds = check_metrics_retention(
            body.metrics_retention_seconds
        )
    if body.metrics_interval_seconds is not None:
        settings.metrics_interval_seconds = check_metrics_interval(
            body.metrics_interval_seconds
        )
    if body.vm_console_non_admin_access is not None:
        settings.vm_console_non_admin_access = body.vm_console_non_admin_access
    if diff := changes(before, _snapshot(settings)):
        await record(db, user, "settings.update", target_type="settings", details=diff)
    if settings.metrics_interval_seconds != before["metricsIntervalSeconds"]:
        # apply now; agents that miss it are caught up from their agent_status
        hosts = (
            await db.execute(select(Host.short_id).where(Host.agent_version.is_not(None)))
        ).scalars()
        for short_id in hosts:
            await send_metrics_config(short_id, settings.metrics_interval_seconds)
    return _out(settings)
