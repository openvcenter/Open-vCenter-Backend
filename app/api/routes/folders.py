from __future__ import annotations

from fastapi import APIRouter, Query, Response, status
from sqlalchemy import select

from ...models import Folder
from ...schemas import FolderCreate, FolderOut, FolderUpdate
from ...services.audit import changes, record
from ...services.organization import (
    create_folder,
    delete_folder,
    rename_folder,
)
from ...services.serializers import folder_out
from ..deps import CurrentUser, DbSession, Scope
from ..errors import not_found

router = APIRouter(tags=["folders"])


@router.get("/folders", response_model=list[FolderOut])
async def list_folders(
    db: DbSession,
    scope: Scope,
    host_id: str | None = Query(default=None, alias="hostId"),
    cluster_id: str | None = Query(default=None, alias="clusterId"),
) -> list[FolderOut]:
    stmt = select(Folder).order_by(Folder.name)
    if host_id is not None:
        stmt = stmt.where(Folder.host_id == host_id)
    if cluster_id is not None:
        stmt = stmt.where(Folder.cluster_id == cluster_id)
    folders = (await db.execute(stmt)).scalars().all()
    return [folder_out(f) for f in folders if scope.sees_folder(f.id)]


@router.post("/folders", response_model=FolderOut, status_code=status.HTTP_201_CREATED)
async def add_folder(
    body: FolderCreate, db: DbSession, scope: Scope, user: CurrentUser
) -> FolderOut:
    scope.require(
        "folder.manage",
        ("cluster", body.cluster_id) if body.cluster_id else ("host", body.host_id),
    )
    folder = await create_folder(
        db, name=body.name, cluster_id=body.cluster_id, host_id=body.host_id
    )
    await record(db, user, "folder.create", folder)
    return folder_out(folder)


async def _managed_folder(db: DbSession, scope: Scope, folder_id: str) -> Folder:
    folder = await db.get(Folder, folder_id)
    if folder is None:
        raise not_found("Folder")
    # renaming / deleting a folder is managed from where it lives (its cluster or
    # standalone host, or above): a permission on the folder covers its VMs,
    # never the folder itself
    owner = ("cluster", folder.cluster_id) if folder.cluster_id else ("host", folder.host_id)
    scope.require("folder.manage", owner)
    return folder


@router.patch("/folders/{folder_id}", response_model=FolderOut)
async def patch_folder(
    folder_id: str, body: FolderUpdate, db: DbSession, scope: Scope, user: CurrentUser
) -> FolderOut:
    folder = await _managed_folder(db, scope, folder_id)
    before = folder.name
    folder = await rename_folder(db, folder, body.name)
    if diff := changes({"name": before}, {"name": folder.name}):
        await record(db, user, "folder.rename", folder, details=diff)
    return folder_out(folder)


@router.delete("/folders/{folder_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_folder(
    folder_id: str, db: DbSession, scope: Scope, user: CurrentUser
) -> Response:
    folder = await _managed_folder(db, scope, folder_id)
    event = await record(db, user, "folder.delete", folder)
    event.details = {"vmsDetached": await delete_folder(db, folder)}
    return Response(status_code=status.HTTP_204_NO_CONTENT)
