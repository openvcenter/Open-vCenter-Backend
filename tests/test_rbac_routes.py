"""Privilege checks on the routes: no DB, no agent - the caller's `Access` and a
fake session are injected, and anything that would act is made to fail loudly."""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest

from app.api import deps
from app.api.deps import Identity, get_identity, get_scope
from app.api.errors import ApiError
from app.api.routes import vms as vm_routes
from app.db import get_session
from app.ids import new_id
from app.main import app
from app.models import Cluster, Folder, Host, User, Vm
from app.services.privileges import READ_ONLY_ROLE_ID
from app.services.rbac import GLOBAL, Access, PermRow, Principals, Topology
from app.services.vms import ACTION_MAP, VM_ACTION_PRIVILEGES

VM = SimpleNamespace(
    id="vm-1",
    name="db01",
    host_id="h-1",
    cluster_id="c-1",
    folder_id="f-1",
    vm_uuid="guid-1",
    highly_available=True,
    tags=[],
)
HOST = SimpleNamespace(id="h-1", name="node1", fqdn="node1.lab", ip_address=None, cluster_id="c-1")


class _Result:
    def __init__(self, value: object) -> None:
        self.value = value

    def scalar_one_or_none(self) -> object:
        return self.value

    def scalars(self) -> _Scalars:
        return _Scalars([self.value] if self.value is not None else [])


class _Scalars(list):
    def all(self) -> list:
        return list(self)


class FakeSession:
    """Every query answers with the one VM / host; writes are never expected."""

    async def execute(self, stmt):
        entity = stmt.column_descriptions[0]["entity"]
        return _Result(HOST if entity is Host else VM)

    async def scalar(self, stmt):
        return False

    async def get(self, model, oid):
        if model is Vm:
            return VM
        if model is Host:
            return HOST
        if model in (Cluster, Folder):
            return SimpleNamespace(id=oid, name=oid, cluster_id="c-1", host_id=None)
        return None

    def add(self, obj) -> None:  # pragma: no cover - a write means a missed check
        raise AssertionError(f"unexpected write: {obj!r}")


def _perm(scope, privileges, role_id=None) -> PermRow:
    return PermRow(
        id=new_id(),
        group_id="helpdesk",
        role_id=role_id or new_id(),
        role_name="test",
        scope_type=scope[0],
        scope_id=scope[1],
        propagate=True,
        privileges=frozenset(privileges),
    )


def _access(*rows: PermRow) -> Access:
    topo = Topology(
        cluster_ids={"c-1"},
        host_cluster={"h-1": "c-1"},
        folder_owner={"f-1": ("c-1", None)},
    )
    return Access(Principals(groups=("helpdesk",)), rows, topo)


READ_ONLY = _perm(GLOBAL, (), READ_ONLY_ROLE_ID)


@pytest.fixture
def client_as(monkeypatch):
    """ASGI client acting as a caller with the given Access."""

    async def no_session():
        yield FakeSession()

    async def must_not_run(*args, **kwargs):
        raise AssertionError("the operation ran without its privilege")

    for name in (
        "request_vm_action",
        "request_vm_create",
        "request_vm_clone",
        "remove_vm_from_inventory",
        "move_vm_to_folder",
        "set_vm_tags",
    ):
        monkeypatch.setattr(vm_routes, name, must_not_run)

    def make(access: Access) -> httpx.AsyncClient:
        user = User(id="u-1", email="helpdesk@lab", display_name="Help Desk")
        app.dependency_overrides[get_session] = no_session
        app.dependency_overrides[get_identity] = lambda: Identity(user, access.principals)
        app.dependency_overrides[get_scope] = lambda: access
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")

    yield make
    app.dependency_overrides.clear()


def test_every_vm_action_names_its_privilege() -> None:
    assert set(VM_ACTION_PRIVILEGES) == set(ACTION_MAP)
    assert VM_ACTION_PRIVILEGES["refresh"] is None


VM_CALLS = [
    *(
        ("POST", f"/api/vms/vm-1/actions/{a}", None)
        for a in ACTION_MAP
        if a not in ("delete", "refresh")
    ),
    ("DELETE", "/api/vms/vm-1", None),
    ("DELETE", "/api/vms/vm-1/from-inventory", None),
    ("PATCH", "/api/vms/vm-1", {"folderId": None}),
    ("PUT", "/api/vms/vm-1/tags", {"tagIds": []}),
    ("POST", "/api/vms", {"name": "new01", "hostId": "h-1"}),
    (
        "POST",
        "/api/vms/clone",
        {"name": "new01", "hostId": "h-1", "source": "vm", "sourceVmId": "vm-1"},
    ),
    ("GET", "/api/vms/vm-1/console", None),
]


@pytest.mark.parametrize(("method", "url", "body"), VM_CALLS)
async def test_read_only_gets_403_on_every_vm_operation(client_as, method, url, body) -> None:
    async with client_as(_access(READ_ONLY)) as client:
        resp = await client.request(method, url, json=body)
    assert resp.status_code == 403, resp.text
    assert resp.json()["error"]["code"] == "FORBIDDEN"


async def test_read_only_still_reads_the_vm(client_as) -> None:
    async with client_as(_access(READ_ONLY)) as client:
        resp = await client.get("/api/vms/vm-1/thumbnail")
    # past the access check: the fake session has no thumbnail
    assert resp.status_code == 404
    assert resp.json()["error"]["message"] == "Thumbnail not found"


async def test_invisible_vm_is_forbidden(client_as) -> None:
    async with client_as(_access()) as client:
        resp = await client.get("/api/vms/vm-1/console")
    assert resp.status_code == 403


async def test_power_user_powers_on(client_as, monkeypatch) -> None:
    async def reached(db, vm, action, **kwargs):
        raise ApiError("REACHED", action, 418)

    monkeypatch.setattr(vm_routes, "request_vm_action", reached)
    access = _access(_perm(("folder", "f-1"), {"vm.power"}))
    async with client_as(access) as client:
        ok = await client.post("/api/vms/vm-1/actions/start")
        denied = await client.delete("/api/vms/vm-1")
    assert ok.status_code == 418 and ok.json()["error"]["message"] == "start"
    assert denied.status_code == 403


async def test_migrate_needs_create_on_the_destination(client_as) -> None:
    access = _access(_perm(("vm", "vm-1"), {"vm.migrate"}))
    async with client_as(access) as client:
        resp = await client.post(
            "/api/vms/vm-1/actions/migrate", json={"params": {"target_host": "node2"}}
        )
    assert resp.status_code == 403
    assert "vm.create" in resp.json()["error"]["message"]


async def test_console_needs_vm_console(client_as) -> None:
    access = _access(_perm(("vm", "vm-1"), {"vm.console"}))
    async with client_as(access) as client:
        resp = await client.get("/api/vms/vm-1/console")
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"hostname": "node1.lab", "port": 2179, "vmGuid": "guid-1"}


ADMIN_ONLY_CALLS = [
    ("POST", "/api/clusters", {"name": "c2"}),
    ("DELETE", "/api/clusters/c-1", None),
    ("POST", "/api/hosts", {"name": "h2"}),
    ("DELETE", "/api/hosts/h-1", None),
    ("GET", "/api/hosts/h-1/agent-config", None),
    ("GET", "/api/hosts/h-1/agent-install-url", None),
    ("POST", "/api/hosts/h-1/actions/update-agent", None),
    ("POST", "/api/hosts/h-1/actions/suspend", None),
    ("POST", "/api/hosts/h-1/actions/restart", None),
    ("GET", "/api/hosts/h-1/console", None),
    ("POST", "/api/folders", {"name": "f2", "clusterId": "c-1"}),
    ("DELETE", "/api/folders/f-1", None),
    ("POST", "/api/tag-categories", {"name": "env"}),
    ("GET", "/api/audit-events", None),
    ("DELETE", "/api/vm-locks", None),
    ("DELETE", "/api/vm-locks/vm-1", None),
    ("GET", "/api/agent-binaries", None),
    ("POST", "/api/roles", {"name": "Custom", "privileges": []}),
    (
        "POST",
        "/api/permissions",
        {
            "group": "x",
            "roleId": READ_ONLY_ROLE_ID,
            "scopeType": "global",
        },
    ),
    ("GET", "/api/permissions?scopeType=global", None),
]


@pytest.mark.parametrize(("method", "url", "body"), ADMIN_ONLY_CALLS)
async def test_former_admin_routes_need_their_privilege(client_as, method, url, body) -> None:
    async with client_as(_access(READ_ONLY)) as client:
        resp = await client.request(method, url, json=body)
    assert resp.status_code == 403, resp.text


def test_claim_list_reads_dot_paths(monkeypatch) -> None:
    claims = {"realm_access": {"roles": ["a", "b"]}, "groups": "g1 g2"}
    assert deps._claim_list(claims, "realm_access.roles") == ["a", "b"]
    assert deps._claim_list(claims, "groups") == ["g1", "g2"]
    assert deps._claim_list(claims, "missing.path") == []


# A permission on a host / cluster covers what is inside it, never the object
# itself: creating, renaming, moving and removing hosts / clusters is global-only.
SELF_MANAGEMENT_CALLS = [
    ("POST", "/api/hosts", {"name": "h2", "clusterId": "c-1"}),
    ("PATCH", "/api/hosts/h-1", {"name": "renamed"}),
    ("PATCH", "/api/hosts/h-1", {"clusterId": None}),
    ("DELETE", "/api/hosts/h-1", None),
    ("GET", "/api/hosts/h-1/agent-config", None),
    ("PATCH", "/api/clusters/c-1", {"name": "renamed"}),
    ("DELETE", "/api/clusters/c-1", None),
]


@pytest.mark.parametrize(("method", "url", "body"), SELF_MANAGEMENT_CALLS)
async def test_cluster_admin_cannot_manage_the_cluster_or_its_hosts(
    client_as, method, url, body
) -> None:
    every = {"host.manage", "host.config", "cluster.manage", "folder.manage", "vm.create"}
    access = _access(_perm(("cluster", "c-1"), every))
    async with client_as(access) as client:
        resp = await client.request(method, url, json=body)
    assert resp.status_code == 403, resp.text
