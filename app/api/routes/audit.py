from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query

from ...models import Vm
from ...schemas import AuditEventOut, AuditEventPage
from ...services.audit import AuditFilter, list_events
from ..deps import DbSession, Scope
from ..errors import forbidden

router = APIRouter(tags=["audit"])


def _aware(value: datetime | None) -> datetime | None:
    """A bound without an offset is taken as UTC (the column is timestamptz)."""
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def _str(value: UUID | None) -> str | None:
    return str(value) if value is not None else None


async def _require_object_audit(
    db: DbSession,
    scope: Scope,
    target_type: str | None,
    target_id: UUID | None,
    host_id: UUID | None,
    cluster_id: UUID | None,
) -> None:
    if cluster_id is not None:
        return scope.require("audit.read", ("cluster", str(cluster_id)))
    if host_id is not None:
        return scope.require("audit.read", ("host", str(host_id)))
    if target_id is not None:
        oid = str(target_id)
        if target_type in (None, "vm") and (vm := await db.get(Vm, oid)) is not None:
            return scope.require_vm("audit.read", vm)
        if target_type in ("cluster", "host", "folder"):
            return scope.require("audit.read", (target_type, oid))
    raise forbidden("Missing privilege 'audit.read'")


@router.get("/audit-events", response_model=AuditEventPage)
async def get_audit_events(
    db: DbSession,
    scope: Scope,
    actor: Annotated[
        str | None, Query(description="Partial match on the actor's email or name")
    ] = None,
    action: Annotated[str | None, Query(description="Exact action, e.g. vm.delete")] = None,
    target_type: Annotated[str | None, Query(alias="targetType")] = None,
    target_id: Annotated[UUID | None, Query(alias="targetId")] = None,
    host_id: Annotated[
        UUID | None,
        Query(alias="hostId", description="The host and everything that was on it"),
    ] = None,
    cluster_id: Annotated[
        UUID | None,
        Query(alias="clusterId", description="The cluster and everything that was in it"),
    ] = None,
    outcome: Annotated[str | None, Query()] = None,
    since: Annotated[
        datetime | None, Query(description="Inclusive lower bound (ISO 8601)")
    ] = None,
    until: Annotated[
        datetime | None, Query(description="Exclusive upper bound (ISO 8601)")
    ] = None,
    q: Annotated[
        str | None, Query(description="Partial match on target name or actor")
    ] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    cursor: Annotated[
        str | None, Query(description="`nextCursor` of the previous page")
    ] = None,
) -> AuditEventPage:
    """The audit log, newest first. Needs `audit.read` globally - or on the
    object a `targetId` / `hostId` / `clusterId` filter narrows it to (the
    per-object Events tabs)."""
    if not scope.can("audit.read"):
        await _require_object_audit(db, scope, target_type, target_id, host_id, cluster_id)
    rows, next_cursor = await list_events(
        db,
        AuditFilter(
            actor=actor,
            action=action,
            target_type=target_type,
            target_id=_str(target_id),
            host_id=_str(host_id),
            cluster_id=_str(cluster_id),
            outcome=outcome,
            since=_aware(since),
            until=_aware(until),
            q=q,
        ),
        limit=limit,
        cursor=cursor,
    )
    return AuditEventPage(
        items=[AuditEventOut.model_validate(r) for r in rows], next_cursor=next_cursor
    )
