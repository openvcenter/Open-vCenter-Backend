from __future__ import annotations

from .common import CamelModel


class MeOut(CamelModel):
    id: str
    email: str
    display_name: str | None = None
    roles: list[str] = []
    groups: list[str] = []
    # carries the admin role: every privilege everywhere
    superuser: bool = False
    global_privileges: list[str] = []


class HealthOut(CamelModel):
    ok: bool
    db: bool
    cache: bool
    rabbit: bool
