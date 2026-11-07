from __future__ import annotations

from .common import CamelModel


class AppSettingsOut(CamelModel):
    metrics_retention_seconds: int
    # the presets PATCH accepts for metrics_retention_seconds
    metrics_retention_options: list[int]
    metrics_interval_seconds: int
    # the presets PATCH accepts for metrics_interval_seconds
    metrics_interval_options: list[int]
    vm_console_non_admin_access: bool


class AppSettingsUpdate(CamelModel):
    """Only the fields sent are changed."""

    metrics_retention_seconds: int | None = None
    metrics_interval_seconds: int | None = None
    vm_console_non_admin_access: bool | None = None
