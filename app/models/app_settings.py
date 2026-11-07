from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, func, text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base

# Application-wide preferences edited from the frontend's Application Preferences
# dialog (GET/PATCH /settings). One row, id 1: each option is a typed column, so a
# new option is a migration plus a field (app.services.app_settings).
APP_SETTINGS_ID = 1


class AppSettings(Base):
    __tablename__ = "app_settings"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=False, default=APP_SETTINGS_ID
    )
    # quick host/VM metrics: how long a sample is kept before it is pruned
    metrics_retention_seconds: Mapped[int] = mapped_column(
        Integer, nullable=False, default=3600, server_default=text("3600")
    )
    # quick host/VM metrics: the agents' collection window (pushed to them with
    # set_metrics_config, see app.services.app_settings)
    metrics_interval_seconds: Mapped[int] = mapped_column(
        Integer, nullable=False, default=300, server_default=text("300")
    )
    # let users who aren't Hyper-V administrators open a VM console
    # (Grant-VMConnectAccess). Stored only - not enforced yet.
    vm_console_non_admin_access: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
