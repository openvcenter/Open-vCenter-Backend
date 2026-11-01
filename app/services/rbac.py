"""Authorization: who may see and do what on which inventory object.

A permission grants a role (a set of privileges) to a principal on an object;
with `propagate` it also applies to everything below that object. Principals
are the roles and groups the identity provider reports for the signed-in user
(`Principals`) - permissions are never granted to individual users.

The inventory is a tree with one twist: a VM has two parents.

    global → cluster → host → VM            (host path)
    global → cluster → folder → VM          (folder path, cluster folder)
    global → host → folder → VM             (folder path, standalone-host folder)

Resolution, for one object:

- A *level* (one object on the path) collects the caller's permissions on it;
  on an ancestor only the ones with `propagate`. Privileges of every matching
  row are combined; a "No access" row makes the level BLOCKED.
- On a path, the most specific level with matching rows wins.
- A VM resolves its own level first: if it has rows, that result is final.
  Otherwise the two paths are combined: the VM is visible if either path
  grants, and gets the union of both.
- Visible = resolves to a privilege set (possibly empty: Read-only). Nothing
  above a granted object becomes visible - a folder grant shows that folder and
  its VMs, not the host or cluster around it.

The configured admin role (`OVC_ADMIN_ROLE`) is a superuser: every privilege
everywhere, with no permission row (break-glass; cannot be locked out).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field

from sqlalchemy import ColumnElement, and_, delete, exists, false, or_, select, true
from sqlalchemy.ext.asyncio import AsyncSession

from ..api.errors import forbidden
from ..config import get_settings
from ..models import Cluster, Folder, Host, Permission, Role, RolePrivilege, Vm
from .privileges import ALL_PRIVILEGES, BUILTIN_ROLE_PRIVILEGES, NO_ACCESS_ROLE_ID

# (scope_type, scope_id); scope_id is None only for global
Ref = tuple[str, str | None]
GLOBAL: Ref = ("global", None)


class _Blocked:
    def __repr__(self) -> str:
        return "BLOCKED"


BLOCKED = _Blocked()
LevelResult = frozenset[str] | _Blocked | None


@dataclass(frozen=True)
class Principals:
    """Identity-provider-neutral principal set of the caller."""

    roles: tuple[str, ...] = ()
    groups: tuple[str, ...] = ()

    def keys(self) -> set[tuple[str, str]]:
        return {("role", r) for r in self.roles} | {("group", g) for g in self.groups}

    @property
    def superuser(self) -> bool:
        return get_settings().admin_role in self.roles


@dataclass(frozen=True)
class PermRow:
    id: str
    principal_type: str
    principal_id: str
    role_id: str
    role_name: str
    scope_type: str
    scope_id: str | None
    propagate: bool
    privileges: frozenset[str]

    @property
    def no_access(self) -> bool:
        return self.role_id == NO_ACCESS_ROLE_ID


# --- pure core ---------------------------------------------------------------


def level_result(rows: Iterable[PermRow], *, direct: bool) -> LevelResult:
    """Result of one level. `direct` = the object being resolved itself, where
    non-propagating rows count too."""
    matched = [r for r in rows if direct or r.propagate]
    if not matched:
        return None
    if any(r.no_access for r in matched):
        return BLOCKED
    return frozenset().union(*(r.privileges for r in matched))


def chain_result(
    levels: Iterable[tuple[Ref, list[PermRow], bool]],
) -> tuple[LevelResult, Ref | None]:
    """First level (most specific first) with matching rows wins."""
    for ref, rows, direct in levels:
        result = level_result(rows, direct=direct)
        if result is not None:
            return result, ref
    return None, None


def combine_vm(
    direct: LevelResult, folder_path: LevelResult, host_path: LevelResult
) -> frozenset[str] | None:
    """VM privileges from its own level and both inherited paths (None = hidden)."""
    if direct is not None:
        return None if direct is BLOCKED else direct  # type: ignore[return-value]
    sets = [r for r in (folder_path, host_path) if isinstance(r, frozenset)]
    if not sets:
        return None
    return frozenset().union(*sets)


# --- per-request access ------------------------------------------------------


@dataclass
class Topology:
    host_cluster: dict[str, str | None] = field(default_factory=dict)
    # folder id -> (cluster_id, host_id); exactly one is set
    folder_owner: dict[str, tuple[str | None, str | None]] = field(default_factory=dict)
    cluster_ids: set[str] = field(default_factory=set)


class Access:
    """What the caller may see and do. Built once per request (`load_access`)."""

    def __init__(
        self,
        principals: Principals,
        rows: Iterable[PermRow] = (),
        topology: Topology | None = None,
    ) -> None:
        self.principals = principals
        self.superuser = principals.superuser
        self.topology = topology or Topology()
        self._by_scope: dict[Ref, list[PermRow]] = defaultdict(list)
        for r in rows:
            self._by_scope[(r.scope_type, r.scope_id)].append(r)
        self._visibility: _Visibility | None = None

    # --- chains ---

    def _rows(self, ref: Ref) -> list[PermRow]:
        return self._by_scope.get(ref, [])

    def chain(self, ref: Ref) -> list[Ref]:
        """`ref` and its ancestors, most specific first (VMs: see vm_paths)."""
        kind, oid = ref
        if kind == "global":
            return [GLOBAL]
        if kind == "cluster":
            return [ref, GLOBAL]
        if kind == "host":
            cluster_id = self.topology.host_cluster.get(oid)  # type: ignore[arg-type]
            return [ref, *(self.chain(("cluster", cluster_id)) if cluster_id else [GLOBAL])]
        if kind == "folder":
            cluster_id, host_id = self.topology.folder_owner.get(oid, (None, None))  # type: ignore[arg-type]
            if cluster_id:
                return [ref, *self.chain(("cluster", cluster_id))]
            if host_id:
                return [ref, *self.chain(("host", host_id))]
            return [ref, GLOBAL]
        raise ValueError(f"no single chain for {kind}")

    def _levels(self, refs: list[Ref], *, first_direct: bool):
        return [(r, self._rows(r), first_direct and i == 0) for i, r in enumerate(refs)]

    def _path(self, refs: list[Ref], *, first_direct: bool) -> LevelResult:
        return chain_result(self._levels(refs, first_direct=first_direct))[0]

    def vm_paths(self, host_id: str | None, folder_id: str | None) -> dict[str, list[Ref]]:
        paths: dict[str, list[Ref]] = {}
        if folder_id:
            paths["folder"] = self.chain(("folder", folder_id))
        paths["host"] = self.chain(("host", host_id)) if host_id else [GLOBAL]
        return paths

    # --- privileges ---

    def privileges(self, ref: Ref) -> frozenset[str] | None:
        """Privileges on a cluster / host / folder / global (None = invisible)."""
        if self.superuser:
            return ALL_PRIVILEGES
        result = self._path(self.chain(ref), first_direct=True)
        return result if isinstance(result, frozenset) else None

    def vm_privileges(
        self, vm_id: str, host_id: str | None, folder_id: str | None
    ) -> frozenset[str] | None:
        if self.superuser:
            return ALL_PRIVILEGES
        direct = level_result(self._rows(("vm", vm_id)), direct=True)
        paths = self.vm_paths(host_id, folder_id)
        folder = self._path(paths["folder"], first_direct=False) if "folder" in paths else None
        host = self._path(paths["host"], first_direct=False)
        return combine_vm(direct, folder, host)

    def privileges_for_vm(self, vm: Vm) -> frozenset[str] | None:
        return self.vm_privileges(vm.id, vm.host_id, vm.folder_id)

    def can(self, privilege: str, ref: Ref = GLOBAL) -> bool:
        privs = self.privileges(ref)
        return privs is not None and privilege in privs

    def can_vm(self, privilege: str, vm: Vm) -> bool:
        privs = self.privileges_for_vm(vm)
        return privs is not None and privilege in privs

    def holds_anywhere(self, privilege: str) -> bool:
        """Granted `privilege` on at least one object (not necessarily visible)."""
        return self.superuser or any(
            privilege in r.privileges for rows in self._by_scope.values() for r in rows
        )

    def require(self, privilege: str, ref: Ref = GLOBAL) -> None:
        if not self.can(privilege, ref):
            raise forbidden(f"Missing privilege '{privilege}'")

    def require_vm(self, privilege: str, vm: Vm) -> None:
        if not self.can_vm(privilege, vm):
            raise forbidden(f"Missing privilege '{privilege}'")

    # --- visibility (list filtering) ---

    @property
    def all(self) -> bool:
        """Sees every object: lets list routes skip filtering."""
        return self._vis().all

    def sees_cluster(self, cluster_id: str | None) -> bool:
        return cluster_id is not None and (self.all or cluster_id in self._vis().cluster_ids)

    def sees_host(self, host_id: str | None) -> bool:
        return host_id is not None and (self.all or host_id in self._vis().host_ids)

    def sees_folder(self, folder_id: str | None) -> bool:
        return folder_id is not None and (self.all or folder_id in self._vis().folder_ids)

    def vm_visible(self, vm: Vm) -> bool:
        return self.all or self.privileges_for_vm(vm) is not None

    async def sees_host_context(self, db: AsyncSession, host_id: str) -> bool:
        """Visible, or holds a visible VM: enough to read the host's details
        (VM dialogs need its hardware, switches, state) - but it is not listed."""
        if self.sees_host(host_id):
            return True
        return bool(
            await db.scalar(select(exists().where(Vm.host_id == host_id, self.vm_clause())))
        )

    async def sees_cluster_context(self, db: AsyncSession, cluster_id: str) -> bool:
        if self.sees_cluster(cluster_id):
            return True
        return bool(
            await db.scalar(
                select(exists().where(Vm.cluster_id == cluster_id, self.vm_clause()))
            )
        )

    def vm_clause(self) -> ColumnElement[bool]:
        """SQL twin of :meth:`vm_visible`, for filtering or counting in a query."""
        vis = self._vis()
        if vis.all:
            return true()
        inherited = []
        if vis.vm_hosts:
            inherited.append(Vm.host_id.in_(vis.vm_hosts))
        if vis.vm_folders:
            inherited.append(Vm.folder_id.in_(vis.vm_folders))
        clauses = []
        if vis.vm_allow:
            clauses.append(Vm.id.in_(vis.vm_allow))
        if inherited:
            clauses.append(
                and_(Vm.id.not_in(vis.vm_direct), or_(*inherited))
                if vis.vm_direct
                else or_(*inherited)
            )
        return or_(*clauses) if clauses else false()

    def _vis(self) -> _Visibility:
        if self._visibility is None:
            self._visibility = self._compute_visibility()
        return self._visibility

    def _compute_visibility(self) -> _Visibility:
        if self.superuser:
            return _Visibility(all=True)
        global_rows = self._rows(GLOBAL)
        if (
            set(self._by_scope) <= {GLOBAL}
            and all(r.propagate for r in global_rows)
            and isinstance(level_result(global_rows, direct=True), frozenset)
        ):
            return _Visibility(all=True)  # only propagating global rows, and they grant
        topo = self.topology
        vis = _Visibility()
        vis.cluster_ids = {
            c for c in topo.cluster_ids if self.privileges(("cluster", c)) is not None
        }
        for host_id in topo.host_cluster:
            ref = ("host", host_id)
            if self.privileges(ref) is not None:
                vis.host_ids.add(host_id)
            if isinstance(self._path(self.chain(ref), first_direct=False), frozenset):
                vis.vm_hosts.add(host_id)
        for folder_id in topo.folder_owner:
            ref = ("folder", folder_id)
            if self.privileges(ref) is not None:
                vis.folder_ids.add(folder_id)
            if isinstance(self._path(self.chain(ref), first_direct=False), frozenset):
                vis.vm_folders.add(folder_id)
        for (kind, vm_id), rows in self._by_scope.items():
            if kind != "vm":
                continue
            vis.vm_direct.add(vm_id)  # type: ignore[arg-type]
            if isinstance(level_result(rows, direct=True), frozenset):
                vis.vm_allow.add(vm_id)  # type: ignore[arg-type]
        return vis

    # --- explain ---

    def explain_levels(
        self, refs: list[Ref], *, first_direct: bool
    ) -> tuple[list[dict], Ref | None]:
        levels = self._levels(refs, first_direct=first_direct)
        _, winner = chain_result(levels)
        out = []
        for ref, rows, direct in levels:
            matched = [r for r in rows if direct or r.propagate]
            result = level_result(rows, direct=direct)
            out.append(
                {
                    "ref": ref,
                    "rows": matched,
                    "blocked": result is BLOCKED,
                    "winner": ref == winner,
                }
            )
        return out, winner


@dataclass
class _Visibility:
    all: bool = False
    cluster_ids: set[str] = field(default_factory=set)
    host_ids: set[str] = field(default_factory=set)
    folder_ids: set[str] = field(default_factory=set)
    # VMs of these hosts / folders inherit a grant (unless they have own rows)
    vm_hosts: set[str] = field(default_factory=set)
    vm_folders: set[str] = field(default_factory=set)
    vm_direct: set[str] = field(default_factory=set)  # VMs with own rows
    vm_allow: set[str] = field(default_factory=set)  # … that grant


# --- loading -----------------------------------------------------------------


async def role_privileges(db: AsyncSession, role_ids: Iterable[str]) -> dict[str, frozenset[str]]:
    """Effective privileges per role id (built-ins from code, unknown ignored)."""
    ids = set(role_ids)
    out: dict[str, set[str]] = {rid: set() for rid in ids}
    custom = ids - set(BUILTIN_ROLE_PRIVILEGES)
    if custom:
        rows = await db.execute(
            select(RolePrivilege.role_id, RolePrivilege.privilege).where(
                RolePrivilege.role_id.in_(custom)
            )
        )
        for role_id, priv in rows:
            if priv in ALL_PRIVILEGES:
                out[role_id].add(priv)
    result = {rid: frozenset(p) for rid, p in out.items()}
    for rid in ids & set(BUILTIN_ROLE_PRIVILEGES):
        result[rid] = BUILTIN_ROLE_PRIVILEGES[rid]
    return result


async def load_rows(
    db: AsyncSession, principals: Principals, *, scope: Ref | None = None
) -> list[PermRow]:
    """Permission rows of `principals`, optionally on one object. With no
    principals and a `scope`: every principal's rows on that object."""
    stmt = select(Permission, Role.name).join(Role, Role.id == Permission.role_id)
    keys = principals.keys()
    if keys:
        stmt = stmt.where(
            or_(
                *(
                    and_(Permission.principal_type == t, Permission.principal_id == i)
                    for t, i in sorted(keys)
                )
            )
        )
    elif scope is None:
        return []
    if scope is not None:
        stmt = stmt.where(
            Permission.scope_type == scope[0],
            Permission.scope_id.is_(None) if scope[1] is None else Permission.scope_id == scope[1],
        )
    perms = (await db.execute(stmt)).all()
    privs = await role_privileges(db, {p.role_id for p, _ in perms})
    return [to_row(p, name, privs[p.role_id]) for p, name in perms]


def to_row(p: Permission, role_name: str, privileges: frozenset[str]) -> PermRow:
    return PermRow(
        id=p.id,
        principal_type=p.principal_type,
        principal_id=p.principal_id,
        role_id=p.role_id,
        role_name=role_name,
        scope_type=p.scope_type,
        scope_id=p.scope_id,
        propagate=p.propagate,
        privileges=privileges,
    )


async def load_topology(db: AsyncSession) -> Topology:
    topo = Topology()
    topo.cluster_ids = set((await db.execute(select(Cluster.id))).scalars())
    topo.host_cluster = dict((await db.execute(select(Host.id, Host.cluster_id))).tuples().all())
    topo.folder_owner = {
        fid: (cid, hid)
        for fid, cid, hid in await db.execute(select(Folder.id, Folder.cluster_id, Folder.host_id))
    }
    return topo


async def load_access(db: AsyncSession, principals: Principals) -> Access:
    if principals.superuser:
        return Access(principals)
    rows = await load_rows(db, principals)
    if not rows:
        return Access(principals)
    return Access(principals, rows, await load_topology(db))


# --- maintenance -------------------------------------------------------------


async def delete_permissions(db: AsyncSession, scope_type: str, ids: Iterable[str]) -> None:
    """Drop the permissions on deleted objects (scope_id has no FK)."""
    id_list = [i for i in ids if i]
    if id_list:
        await db.execute(
            delete(Permission).where(
                Permission.scope_type == scope_type, Permission.scope_id.in_(id_list)
            )
        )


_SCOPE_TABLES = {"cluster": Cluster, "host": Host, "folder": Folder, "vm": Vm}


async def delete_orphan_permissions(db: AsyncSession) -> int:
    """Safety net for objects removed by FK cascades or out-of-band deletes."""
    removed = 0
    for scope_type, model in _SCOPE_TABLES.items():
        result = await db.execute(
            delete(Permission).where(
                Permission.scope_type == scope_type,
                ~select(model.id).where(model.id == Permission.scope_id).exists(),
            )
        )
        removed += result.rowcount or 0
    return removed
