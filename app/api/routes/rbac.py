"""Roles, permissions and privilege queries (see services/rbac.py)."""

from __future__ import annotations

from fastapi import APIRouter, Query, Response, status
from sqlalchemy import func, select
from sqlalchemy.orm import noload

from ...models import Cluster, Folder, Host, Permission, Role, RolePrivilege, Vm
from ...schemas import (
    EffectiveLevelOut,
    EffectiveOut,
    EffectivePathOut,
    MyPrivilegesOut,
    PermissionCreate,
    PermissionListOut,
    PermissionOut,
    PermissionUpdate,
    PrincipalOut,
    PrivilegeOut,
    RbacCatalogOut,
    RoleClone,
    RoleCreate,
    RoleOut,
    RoleUpdate,
)
from ...services.audit import changes, record
from ...services.privileges import ALL_PRIVILEGES, PRIVILEGES
from ...services.rbac import (
    GLOBAL,
    Access,
    PermRow,
    Principals,
    Ref,
    load_rows,
    load_topology,
    role_privileges,
)
from ...services.vms import VM_ACTION_PRIVILEGES
from ..deps import CurrentUser, DbSession, Scope
from ..errors import ApiError, forbidden, not_found

router = APIRouter(tags=["rbac"])

_MAX_PRIVILEGE_IDS = 200
_SCOPE_MODELS = {"cluster": Cluster, "host": Host, "folder": Folder, "vm": Vm}


def _ordered(privileges) -> list[str]:
    return [p for p in PRIVILEGES if p in privileges]


def _parse_ref(text: str) -> Ref:
    """`global` or `<scopeType>:<id>`."""
    if text == "global":
        return GLOBAL
    kind, _, oid = text.partition(":")
    if kind not in _SCOPE_MODELS or not oid:
        raise ApiError("VALIDATION_ERROR", f"Invalid object reference '{text}'")
    return (kind, oid)


def _scope_ref(scope_type: str, scope_id: str | None) -> Ref:
    if scope_type == "global":
        return GLOBAL
    if not scope_id:
        raise ApiError("VALIDATION_ERROR", "scopeId is required unless scopeType is global")
    return (scope_type, scope_id)


async def _load_object(db: DbSession, ref: Ref):
    """The object a reference names (None for global); 404 when it is gone."""
    if ref == GLOBAL:
        return None
    model = _SCOPE_MODELS[ref[0]]
    obj = (
        await db.execute(select(model).where(model.id == ref[1]).options(noload("*")))
    ).scalar_one_or_none()
    if obj is None:
        raise not_found(ref[0].capitalize())
    return obj


def _privileges_on(scope: Access, ref: Ref, obj) -> frozenset[str] | None:
    if ref[0] == "vm":
        return scope.privileges_for_vm(obj)
    return scope.privileges(ref)


def _require_on(scope: Access, privilege: str, ref: Ref, obj) -> None:
    privs = _privileges_on(scope, ref, obj)
    if privs is None or privilege not in privs:
        raise forbidden(f"Missing privilege '{privilege}'")


async def _names(db: DbSession, refs) -> dict[Ref, str]:
    by_kind: dict[str, set[str]] = {}
    for kind, oid in refs:
        if oid is not None:
            by_kind.setdefault(kind, set()).add(oid)
    names: dict[Ref, str] = {GLOBAL: "Global"}
    for kind, ids in by_kind.items():
        model = _SCOPE_MODELS[kind]
        for oid, name in await db.execute(select(model.id, model.name).where(model.id.in_(ids))):
            names[(kind, oid)] = name
    return names


# ---- catalog & roles ---------------------------------------------------------


@router.get("/rbac/catalog", response_model=RbacCatalogOut)
async def get_catalog(_user: CurrentUser) -> RbacCatalogOut:
    return RbacCatalogOut(
        privileges=[PrivilegeOut(id=p, group=g, label=lbl) for p, (g, lbl) in PRIVILEGES.items()],
        vm_actions=VM_ACTION_PRIVILEGES,
    )


async def _role_out(db: DbSession, role: Role) -> RoleOut:
    privs = (await role_privileges(db, [role.id]))[role.id]
    count = await db.scalar(
        select(func.count()).select_from(Permission).where(Permission.role_id == role.id)
    )
    return RoleOut(
        id=role.id,
        name=role.name,
        description=role.description,
        builtin=role.builtin,
        privileges=_ordered(privs),
        permission_count=count or 0,
    )


@router.get("/roles", response_model=list[RoleOut])
async def list_roles(db: DbSession, _user: CurrentUser) -> list[RoleOut]:
    """Every role (any signed-in user: the Permissions tab shows role names)."""
    roles = (await db.execute(select(Role).order_by(Role.builtin.desc(), Role.name))).scalars()
    roles = list(roles)
    privs = await role_privileges(db, [r.id for r in roles])
    counts = dict(
        (await db.execute(select(Permission.role_id, func.count()).group_by(Permission.role_id)))
        .tuples()
        .all()
    )
    return [
        RoleOut(
            id=r.id,
            name=r.name,
            description=r.description,
            builtin=r.builtin,
            privileges=_ordered(privs[r.id]),
            permission_count=counts.get(r.id, 0),
        )
        for r in roles
    ]


def _check_privileges(privileges: list[str]) -> set[str]:
    unknown = sorted(set(privileges) - ALL_PRIVILEGES)
    if unknown:
        raise ApiError(
            "UNKNOWN_PRIVILEGE",
            f"Unknown privilege(s): {', '.join(unknown)}",
            details={"privileges": unknown},
        )
    return set(privileges)


async def _check_name_free(db: DbSession, name: str, role_id: str | None = None) -> str:
    name = name.strip()
    if not name:
        raise ApiError("VALIDATION_ERROR", "The role name cannot be empty")
    clash = await db.scalar(
        select(Role.id).where(func.lower(Role.name) == name.lower(), Role.id != (role_id or ""))
    )
    if clash:
        raise ApiError(
            "ROLE_EXISTS", f"A role named '{name}' already exists", status.HTTP_409_CONFLICT
        )
    return name


async def _create_role(
    db: DbSession, name: str, description: str | None, privileges: set[str]
) -> Role:
    role = Role(name=await _check_name_free(db, name), description=description, builtin=False)
    db.add(role)
    await db.flush()
    db.add_all(RolePrivilege(role_id=role.id, privilege=p) for p in privileges)
    await db.flush()
    return role


@router.post("/roles", response_model=RoleOut, status_code=status.HTTP_201_CREATED)
async def add_role(body: RoleCreate, db: DbSession, scope: Scope, user: CurrentUser) -> RoleOut:
    scope.require("rbac.manage")
    privileges = _check_privileges(body.privileges)
    role = await _create_role(db, body.name, body.description, privileges)
    await record(db, user, "role.create", role, details={"privileges": _ordered(privileges)})
    return await _role_out(db, role)


async def _editable_role(db: DbSession, scope: Access, role_id: str) -> Role:
    scope.require("rbac.manage")
    role = await db.get(Role, role_id)
    if role is None:
        raise not_found("Role")
    if role.builtin:
        raise ApiError(
            "ROLE_BUILTIN",
            f"'{role.name}' is a built-in role and cannot be changed",
            status.HTTP_409_CONFLICT,
        )
    return role


@router.patch("/roles/{role_id}", response_model=RoleOut)
async def edit_role(
    role_id: str, body: RoleUpdate, db: DbSession, scope: Scope, user: CurrentUser
) -> RoleOut:
    role = await _editable_role(db, scope, role_id)
    old_privs = (await role_privileges(db, [role.id]))[role.id]
    before = {"name": role.name, "description": role.description, "privileges": _ordered(old_privs)}
    fields = body.model_fields_set
    if "name" in fields and body.name is not None:
        role.name = await _check_name_free(db, body.name, role.id)
    if "description" in fields:
        role.description = body.description
    new_privs = set(old_privs)
    if "privileges" in fields and body.privileges is not None:
        new_privs = _check_privileges(body.privileges)
        for priv in old_privs - new_privs:
            await db.delete(await db.get(RolePrivilege, (role.id, priv)))
        db.add_all(RolePrivilege(role_id=role.id, privilege=p) for p in new_privs - old_privs)
    await db.flush()
    after = {"name": role.name, "description": role.description, "privileges": _ordered(new_privs)}
    if diff := changes(before, after):
        await record(db, user, "role.update", role, details=diff)
    return await _role_out(db, role)


@router.post("/roles/{role_id}/clone", response_model=RoleOut, status_code=status.HTTP_201_CREATED)
async def clone_role(
    role_id: str, body: RoleClone, db: DbSession, scope: Scope, user: CurrentUser
) -> RoleOut:
    scope.require("rbac.manage")
    source = await db.get(Role, role_id)
    if source is None:
        raise not_found("Role")
    privileges = set((await role_privileges(db, [source.id]))[source.id])
    role = await _create_role(db, body.name, source.description, privileges)
    await record(db, user, "role.create", role, details={"clonedFrom": source.name})
    return await _role_out(db, role)


@router.delete("/roles/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_role(role_id: str, db: DbSession, scope: Scope, user: CurrentUser) -> Response:
    role = await _editable_role(db, scope, role_id)
    in_use = await db.scalar(
        select(func.count()).select_from(Permission).where(Permission.role_id == role.id)
    )
    if in_use:
        raise ApiError(
            "ROLE_IN_USE",
            f"'{role.name}' is used by {in_use} permission(s) - remove them first",
            status.HTTP_409_CONFLICT,
            details={"permissionCount": in_use},
        )
    await record(db, user, "role.delete", role)
    await db.delete(role)
    await db.flush()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---- permissions -------------------------------------------------------------


def _perm_out(p: Permission | PermRow, role_name: str, names: dict[Ref, str]) -> PermissionOut:
    return PermissionOut(
        id=p.id,
        principal_type=p.principal_type,
        principal_id=p.principal_id,
        role_id=p.role_id,
        role_name=role_name,
        scope_type=p.scope_type,
        scope_id=p.scope_id,
        scope_name=names.get((p.scope_type, p.scope_id)),
        propagate=p.propagate,
        created_by=getattr(p, "created_by", None),
        created_at=getattr(p, "created_at", None),
    )


def _ancestors(access: Access, ref: Ref, obj) -> list[Ref]:
    """Every object above `ref` whose propagating permissions reach it."""
    if ref[0] == "vm":
        paths = access.vm_paths(obj.host_id, obj.folder_id)
        seen: list[Ref] = []
        for path in paths.values():
            for r in path:
                if r not in seen:
                    seen.append(r)
        return seen
    return access.chain(ref)[1:]


async def _permissions_on(db: DbSession, refs: list[Ref]) -> list[tuple[Permission, str]]:
    rows = []
    for ref in refs:
        stmt = (
            select(Permission, Role.name)
            .join(Role, Role.id == Permission.role_id)
            .where(Permission.scope_type == ref[0])
            .where(
                Permission.scope_id.is_(None) if ref[1] is None else Permission.scope_id == ref[1]
            )
            .order_by(Permission.principal_type, Permission.principal_id)
        )
        rows.extend((await db.execute(stmt)).tuples().all())
    return rows


@router.get("/permissions", response_model=PermissionListOut)
async def list_permissions(
    db: DbSession,
    scope: Scope,
    scope_type: str = Query(alias="scopeType"),
    scope_id: str | None = Query(default=None, alias="scopeId"),
) -> PermissionListOut:
    """Permissions defined on an object, and those inherited from above it.
    Needs `rbac.manage` on the object."""
    if scope_type not in ("global", *_SCOPE_MODELS):
        raise ApiError("VALIDATION_ERROR", f"Invalid scopeType '{scope_type}'")
    ref = _scope_ref(scope_type, scope_id)
    obj = await _load_object(db, ref)
    _require_on(scope, "rbac.manage", ref, obj)

    access = Access(Principals(), (), await load_topology(db))
    ancestors = _ancestors(access, ref, obj) if ref != GLOBAL else []
    direct = await _permissions_on(db, [ref])
    inherited = [(p, n) for p, n in await _permissions_on(db, ancestors) if p.propagate]
    names = await _names(db, [ref, *ancestors])
    return PermissionListOut(
        direct=[_perm_out(p, n, names) for p, n in direct],
        inherited=[_perm_out(p, n, names) for p, n in inherited],
    )


async def _grantable_role(db: DbSession, scope: Access, role_id: str, ref: Ref, obj) -> Role:
    """The role, if the caller may hand it out here: no one grants more than
    they hold on the object."""
    role = await db.get(Role, role_id)
    if role is None:
        raise not_found("Role")
    if not scope.superuser:
        granted = (await role_privileges(db, [role.id]))[role.id]
        held = _privileges_on(scope, ref, obj) or frozenset()
        if missing := _ordered(granted - held):
            raise ApiError(
                "ROLE_EXCEEDS_GRANTER",
                f"'{role.name}' includes privileges you do not hold here",
                status.HTTP_403_FORBIDDEN,
                details={"privileges": missing},
            )
    return role


@router.post("/permissions", response_model=PermissionOut, status_code=status.HTTP_201_CREATED)
async def add_permission(
    body: PermissionCreate, db: DbSession, scope: Scope, user: CurrentUser
) -> PermissionOut:
    ref = _scope_ref(body.scope_type, body.scope_id)
    obj = await _load_object(db, ref)
    _require_on(scope, "rbac.manage", ref, obj)
    role = await _grantable_role(db, scope, body.role_id, ref, obj)
    principal_id = body.principal_id.strip()
    if not principal_id:
        raise ApiError("VALIDATION_ERROR", "principalId cannot be empty")

    existing = await db.scalar(
        select(Permission.id).where(
            Permission.principal_type == body.principal_type,
            Permission.principal_id == principal_id,
            Permission.scope_type == ref[0],
            Permission.scope_id.is_(None) if ref[1] is None else Permission.scope_id == ref[1],
        )
    )
    if existing:
        raise ApiError(
            "PERMISSION_EXISTS",
            f"{body.principal_type} '{principal_id}' already has a permission here - edit it",
            status.HTTP_409_CONFLICT,
            details={"permissionId": existing},
        )
    perm = Permission(
        principal_type=body.principal_type,
        principal_id=principal_id,
        role_id=role.id,
        scope_type=ref[0],
        scope_id=ref[1],
        propagate=body.propagate,
        created_by=user.email,
    )
    db.add(perm)
    await db.flush()
    await db.refresh(perm)
    await record(
        db,
        user,
        "permission.create",
        perm,
        details={
            "role": role.name,
            "scopeType": ref[0],
            "scopeId": ref[1],
            "propagate": perm.propagate,
        },
    )
    return _perm_out(perm, role.name, await _names(db, [ref]))


async def _managed_permission(db: DbSession, scope: Access, permission_id: str):
    perm = await db.get(Permission, permission_id)
    if perm is None:
        raise not_found("Permission")
    ref = (perm.scope_type, perm.scope_id)
    obj = await _load_object(db, ref)
    _require_on(scope, "rbac.manage", ref, obj)
    return perm, ref, obj


@router.patch("/permissions/{permission_id}", response_model=PermissionOut)
async def edit_permission(
    permission_id: str, body: PermissionUpdate, db: DbSession, scope: Scope, user: CurrentUser
) -> PermissionOut:
    perm, ref, obj = await _managed_permission(db, scope, permission_id)
    old_role = await db.get(Role, perm.role_id)
    before = {"role": old_role.name if old_role else None, "propagate": perm.propagate}
    role = old_role
    if body.role_id is not None and body.role_id != perm.role_id:
        role = await _grantable_role(db, scope, body.role_id, ref, obj)
        perm.role_id = role.id
    if body.propagate is not None:
        perm.propagate = body.propagate
    await db.flush()
    await db.refresh(perm)
    after = {"role": role.name if role else None, "propagate": perm.propagate}
    if diff := changes(before, after):
        await record(db, user, "permission.update", perm, details=diff)
    return _perm_out(perm, role.name if role else "", await _names(db, [ref]))


@router.delete("/permissions/{permission_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_permission(
    permission_id: str, db: DbSession, scope: Scope, user: CurrentUser
) -> Response:
    perm, ref, _ = await _managed_permission(db, scope, permission_id)
    role = await db.get(Role, perm.role_id)
    await record(
        db,
        user,
        "permission.delete",
        perm,
        details={"role": role.name if role else None, "scopeType": ref[0], "scopeId": ref[1]},
    )
    await db.delete(perm)
    await db.flush()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/principals", response_model=list[PrincipalOut])
async def list_principals(
    db: DbSession,
    scope: Scope,
    q: str | None = Query(default=None),
) -> list[PrincipalOut]:
    """Role and group names to suggest when adding a permission: the caller's
    own plus every principal already used in a permission."""
    if not scope.holds_anywhere("rbac.manage"):
        raise forbidden("Missing privilege 'rbac.manage'")
    known = {("role", r) for r in scope.principals.roles} | {
        ("group", g) for g in scope.principals.groups
    }
    known |= set(
        (await db.execute(select(Permission.principal_type, Permission.principal_id).distinct()))
        .tuples()
        .all()
    )
    needle = (q or "").strip().lower()
    return [
        PrincipalOut(type=t, id=i)
        for t, i in sorted(known, key=lambda k: (k[1].lower(), k[0]))
        if needle in i.lower()
    ][:50]


# ---- privilege queries -------------------------------------------------------


@router.get("/me/privileges", response_model=MyPrivilegesOut)
async def my_privileges(
    db: DbSession,
    scope: Scope,
    ids: str = Query(description="Comma-separated `global` / `<scopeType>:<id>`"),
) -> MyPrivilegesOut:
    """The caller's privileges per object, in one batch (the UI greys out what is
    missing). `null` = the object is not visible (or does not exist)."""
    keys = [k for k in dict.fromkeys(i.strip() for i in ids.split(",")) if k]
    if len(keys) > _MAX_PRIVILEGE_IDS:
        raise ApiError("VALIDATION_ERROR", f"At most {_MAX_PRIVILEGE_IDS} ids per request")
    refs = {k: _parse_ref(k) for k in keys}
    vm_ids = [r[1] for r in refs.values() if r[0] == "vm"]
    vms = (
        {
            v.id: v
            for v in (
                await db.execute(select(Vm).where(Vm.id.in_(vm_ids)).options(noload("*")))
            ).scalars()
        }
        if vm_ids
        else {}
    )
    items: dict[str, list[str] | None] = {}
    for key, ref in refs.items():
        if ref[0] == "vm":
            vm = vms.get(ref[1])
            privs = scope.privileges_for_vm(vm) if vm is not None else None
        else:
            privs = scope.privileges(ref)
        items[key] = _ordered(privs) if privs is not None else None
    return MyPrivilegesOut(items=items)


@router.get("/rbac/effective", response_model=EffectiveOut)
async def effective_permissions(
    db: DbSession,
    scope: Scope,
    principal: str = Query(description="`role:<name>` or `group:<name>`"),
    object_: str = Query(alias="object", description="`global` or `<scopeType>:<id>`"),
) -> EffectiveOut:
    """What one role or group may do on an object, and which permission grants
    it - level by level along each inheritance path. Needs `rbac.manage` there."""
    ptype, _, pid = principal.partition(":")
    if ptype not in ("role", "group") or not pid:
        raise ApiError("VALIDATION_ERROR", "principal must be role:<name> or group:<name>")
    ref = _parse_ref(object_)
    obj = await _load_object(db, ref)
    _require_on(scope, "rbac.manage", ref, obj)

    principals = Principals(roles=(pid,)) if ptype == "role" else Principals(groups=(pid,))
    rows = [] if principals.superuser else await load_rows(db, principals)
    access = Access(principals, rows, await load_topology(db))

    if ref[0] == "vm":
        paths = [("vm", [ref], True)] + [
            (name, refs, False)
            for name, refs in access.vm_paths(obj.host_id, obj.folder_id).items()
        ]
        privs = access.privileges_for_vm(obj)
    else:
        paths = [("object", access.chain(ref), True)]
        privs = access.privileges(ref)

    names = await _names(db, [r for _, refs, _ in paths for r in refs])
    out_paths = []
    for name, refs, first_direct in paths:
        levels, _ = access.explain_levels(refs, first_direct=first_direct)
        out_paths.append(
            EffectivePathOut(
                name=name,
                levels=[
                    EffectiveLevelOut(
                        scope_type=lv["ref"][0],
                        scope_id=lv["ref"][1],
                        scope_name=names.get(lv["ref"]),
                        blocked=lv["blocked"],
                        winner=lv["winner"],
                        permissions=[_perm_out(r, r.role_name, names) for r in lv["rows"]],
                    )
                    for lv in levels
                ],
            )
        )
    return EffectiveOut(
        principal=PrincipalOut(type=ptype, id=pid),
        superuser=access.superuser,
        visible=privs is not None,
        privileges=_ordered(privs or ()),
        paths=out_paths,
    )
