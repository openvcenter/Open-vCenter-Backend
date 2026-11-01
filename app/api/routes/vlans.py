from __future__ import annotations

from fastapi import APIRouter, Query, Response, status

from ...models import Vlan
from ...schemas import VlanCreate, VlanOut, VlanUpdate
from ...services.audit import changes, record
from ...services.networking import (
    create_vlan,
    delete_vlan,
    list_vlans,
    update_vlan,
)
from ...services.serializers import vlan_out
from ..deps import CurrentUser, DbSession, Scope
from ..errors import forbidden, not_found

router = APIRouter(tags=["vlans"])


def _visible(scope: Scope, vlan: Vlan) -> bool:
    return scope.sees_cluster(vlan.cluster_id) or scope.sees_host(vlan.host_id)


def _owner(vlan_or_body) -> tuple[str, str | None]:
    if vlan_or_body.cluster_id:
        return ("cluster", vlan_or_body.cluster_id)
    return ("host", vlan_or_body.host_id)


@router.get("/vlans", response_model=list[VlanOut])
async def get_vlans(
    db: DbSession,
    scope: Scope,
    host_id: str | None = Query(default=None, alias="hostId"),
    cluster_id: str | None = Query(default=None, alias="clusterId"),
) -> list[VlanOut]:
    vlans = await list_vlans(db, host_id=host_id, cluster_id=cluster_id)
    # the VLANs of a visible VM's host / cluster too (NIC pickers need them)
    if host_id is not None and await scope.sees_host_context(db, host_id):
        return [vlan_out(v) for v in vlans]
    if cluster_id is not None and await scope.sees_cluster_context(db, cluster_id):
        return [vlan_out(v) for v in vlans]
    return [vlan_out(v) for v in vlans if _visible(scope, v)]


@router.post("/vlans", response_model=VlanOut, status_code=status.HTTP_201_CREATED)
async def add_vlan(
    body: VlanCreate, db: DbSession, scope: Scope, user: CurrentUser
) -> VlanOut:
    scope.require("host.config", _owner(body))
    vlan = await create_vlan(
        db,
        name=body.name,
        vlan_id=body.vlan_id,
        description=body.description,
        is_default=body.is_default,
        cluster_id=body.cluster_id,
        host_id=body.host_id,
    )
    await record(db, user, "vlan.create", vlan, details=_vlan_fields(vlan))
    return vlan_out(vlan)


def _vlan_fields(vlan: Vlan) -> dict:
    return {
        "name": vlan.name,
        "vlanId": vlan.vlan_id,
        "description": vlan.description,
        "isDefault": vlan.is_default,
    }


async def _get_visible_vlan(db: DbSession, scope: Scope, vlan_id: str) -> Vlan:
    vlan = await db.get(Vlan, vlan_id)
    if vlan is None:
        raise not_found("VLAN")
    if not _visible(scope, vlan):
        raise forbidden()
    scope.require("host.config", _owner(vlan))
    return vlan


@router.patch("/vlans/{vlan_id}", response_model=VlanOut)
async def patch_vlan(
    vlan_id: str, body: VlanUpdate, db: DbSession, scope: Scope, user: CurrentUser
) -> VlanOut:
    vlan = await _get_visible_vlan(db, scope, vlan_id)
    before = _vlan_fields(vlan)
    vlan = await update_vlan(
        db,
        vlan,
        name=body.name,
        description=body.description,
        is_default=body.is_default,
    )
    if diff := changes(before, _vlan_fields(vlan)):
        await record(db, user, "vlan.update", vlan, details=diff)
    return vlan_out(vlan)


@router.delete("/vlans/{vlan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_vlan(
    vlan_id: str, db: DbSession, scope: Scope, user: CurrentUser
) -> Response:
    vlan = await _get_visible_vlan(db, scope, vlan_id)
    await record(db, user, "vlan.delete", vlan, details={"vlanId": vlan.vlan_id})
    await delete_vlan(db, vlan)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
