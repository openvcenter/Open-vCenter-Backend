from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from .common import CamelModel

ScopeType = Literal["global", "cluster", "host", "folder", "vm"]


class PrivilegeOut(CamelModel):
    id: str
    group: str
    label: str


class RbacCatalogOut(CamelModel):
    privileges: list[PrivilegeOut]
    # VM action kind -> privilege it needs (null: visibility is enough)
    vm_actions: dict[str, str | None]


class RoleOut(CamelModel):
    id: str
    name: str
    description: str | None = None
    builtin: bool
    privileges: list[str]
    permission_count: int = 0


class RoleCreate(CamelModel):
    name: str = Field(min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=512)
    privileges: list[str] = []


class RoleUpdate(CamelModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=512)
    privileges: list[str] | None = None


class RoleClone(CamelModel):
    name: str = Field(min_length=1, max_length=128)


class PermissionOut(CamelModel):
    id: str
    # the group as the identity provider names it
    group: str
    role_id: str
    role_name: str
    scope_type: ScopeType
    scope_id: str | None = None
    scope_name: str | None = None
    propagate: bool
    created_by: str | None = None
    created_at: datetime | None = None


class PermissionListOut(CamelModel):
    direct: list[PermissionOut]
    # entries on ancestors that reach this object (propagate=true)
    inherited: list[PermissionOut]


class PermissionCreate(CamelModel):
    group: str = Field(min_length=1, max_length=255)
    role_id: str
    scope_type: ScopeType
    scope_id: str | None = None
    propagate: bool = True


class PermissionUpdate(CamelModel):
    role_id: str | None = None
    propagate: bool | None = None


class MyPrivilegesOut(CamelModel):
    # "<scopeType>:<id>" (or "global") -> privileges; null = not visible
    items: dict[str, list[str] | None]


class EffectiveLevelOut(CamelModel):
    scope_type: ScopeType
    scope_id: str | None = None
    scope_name: str | None = None
    blocked: bool
    # the most specific level with entries on this path - the one that counts
    winner: bool
    permissions: list[PermissionOut]


class EffectivePathOut(CamelModel):
    # "object" for clusters / hosts / folders; "vm", "folder", "host" for a VM
    name: str
    levels: list[EffectiveLevelOut]


class EffectiveOut(CamelModel):
    group: str
    superuser: bool
    visible: bool
    privileges: list[str]
    paths: list[EffectivePathOut]


class ConsoleTargetOut(CamelModel):
    hostname: str
    port: int
    # Hyper-V VM console only: the vmconnect preconnection blob
    vm_guid: str | None = None
