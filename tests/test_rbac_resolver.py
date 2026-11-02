"""Permission resolution (services/rbac.py) on a synthetic inventory, no DB.

global
├── cluster C1 ── host H1 (VMs vm-c1: folder F1, vm-c2: no folder)
│             └── host H2 (VM vm-c3: folder F1)
│   folder F1 (cluster folder of C1)
└── host S1 (standalone) ── VM vm-s1 in host folder F2, vm-s2 no folder
"""

from __future__ import annotations

import random
from types import SimpleNamespace

import pytest

from app.ids import new_id
from app.services.privileges import (
    ADMINISTRATOR_ROLE_ID,
    ALL_PRIVILEGES,
    NO_ACCESS_ROLE_ID,
    READ_ONLY_ROLE_ID,
)
from app.services.rbac import (
    BLOCKED,
    GLOBAL,
    Access,
    PermRow,
    Principals,
    Topology,
    combine_vm,
    level_result,
)

POWER = frozenset({"vm.power", "vm.console"})
CONFIG = frozenset({"vm.config"})


def topology() -> Topology:
    return Topology(
        cluster_ids={"C1"},
        host_cluster={"H1": "C1", "H2": "C1", "S1": None},
        folder_owner={"F1": ("C1", None), "F2": (None, "S1")},
    )


VMS = {
    "vm-c1": SimpleNamespace(id="vm-c1", host_id="H1", folder_id="F1"),
    "vm-c2": SimpleNamespace(id="vm-c2", host_id="H1", folder_id=None),
    "vm-c3": SimpleNamespace(id="vm-c3", host_id="H2", folder_id="F1"),
    "vm-s1": SimpleNamespace(id="vm-s1", host_id="S1", folder_id="F2"),
    "vm-s2": SimpleNamespace(id="vm-s2", host_id="S1", folder_id=None),
}


def perm(
    scope: tuple[str, str | None],
    privileges: frozenset[str] = POWER,
    *,
    group: str = "db-team",
    propagate: bool = True,
    role_id: str | None = None,
) -> PermRow:
    if role_id == NO_ACCESS_ROLE_ID or role_id == READ_ONLY_ROLE_ID:
        privileges = frozenset()
    elif role_id == ADMINISTRATOR_ROLE_ID:
        privileges = ALL_PRIVILEGES
    return PermRow(
        id=new_id(),
        group_id=group,
        role_id=role_id or new_id(),
        role_name="test",
        scope_type=scope[0],
        scope_id=scope[1],
        propagate=propagate,
        privileges=privileges,
    )


def no_access(scope, **kw) -> PermRow:
    return perm(scope, role_id=NO_ACCESS_ROLE_ID, **kw)


def access(*rows: PermRow, groups=("db-team", "ops")) -> Access:
    return Access(Principals(groups=groups), rows, topology())


def vm_privs(a: Access, vm_id: str):
    return a.privileges_for_vm(VMS[vm_id])


# ---- pure core ----------------------------------------------------------------


def test_level_result() -> None:
    assert level_result([], direct=True) is None
    assert level_result([perm(GLOBAL, propagate=False)], direct=False) is None
    assert level_result([perm(GLOBAL, propagate=False)], direct=True) == POWER
    assert level_result([perm(GLOBAL), perm(GLOBAL, CONFIG)], direct=True) == POWER | CONFIG
    assert level_result([perm(GLOBAL), no_access(GLOBAL)], direct=True) is BLOCKED


def test_combine_vm() -> None:
    assert combine_vm(BLOCKED, POWER, POWER) is None
    assert combine_vm(CONFIG, POWER, POWER) == CONFIG
    assert combine_vm(None, POWER, CONFIG) == POWER | CONFIG
    assert combine_vm(None, BLOCKED, CONFIG) == CONFIG  # plain union
    assert combine_vm(None, None, None) is None


# ---- inheritance ------------------------------------------------------------------


def test_nothing_granted_sees_nothing() -> None:
    a = access()
    assert a.privileges(GLOBAL) is None
    assert not a.sees_cluster("C1") and not a.sees_host("H1") and not a.sees_folder("F1")
    assert all(vm_privs(a, v) is None for v in VMS)


def test_global_grant_reaches_everything() -> None:
    a = access(perm(GLOBAL))
    assert a.all
    assert a.privileges(("cluster", "C1")) == POWER
    assert a.privileges(("folder", "F2")) == POWER
    assert all(vm_privs(a, v) == POWER for v in VMS)


def test_cluster_grant_reaches_hosts_folders_and_vms() -> None:
    a = access(perm(("cluster", "C1")))
    assert a.sees_cluster("C1") and a.sees_host("H1") and a.sees_folder("F1")
    assert vm_privs(a, "vm-c1") == POWER and vm_privs(a, "vm-c2") == POWER
    assert not a.sees_host("S1") and vm_privs(a, "vm-s1") is None


def test_standalone_host_grant_reaches_its_folders() -> None:
    a = access(perm(("host", "S1")))
    assert a.sees_folder("F2")
    assert vm_privs(a, "vm-s1") == POWER and vm_privs(a, "vm-s2") == POWER


def test_no_propagate_stays_on_the_object() -> None:
    a = access(perm(("cluster", "C1"), propagate=False))
    assert a.sees_cluster("C1")
    assert not a.sees_host("H1")
    assert vm_privs(a, "vm-c1") is None


def test_folder_grant_shows_only_folder_and_its_vms() -> None:
    a = access(perm(("folder", "F1")))
    assert a.sees_folder("F1")
    assert not a.sees_cluster("C1") and not a.sees_host("H1") and not a.sees_host("H2")
    assert vm_privs(a, "vm-c1") == POWER and vm_privs(a, "vm-c3") == POWER
    assert vm_privs(a, "vm-c2") is None  # same host, but not in the folder


def test_vm_grant_shows_only_the_vm() -> None:
    a = access(perm(("vm", "vm-c2"), propagate=False))
    assert vm_privs(a, "vm-c2") == POWER
    assert not a.sees_host("H1") and not a.sees_cluster("C1")
    assert vm_privs(a, "vm-c1") is None


# ---- most specific wins / union of paths ------------------------------------


def test_most_specific_level_wins_on_a_path() -> None:
    a = access(perm(GLOBAL, CONFIG), perm(("host", "H1"), POWER))
    assert a.privileges(("host", "H1")) == POWER
    assert vm_privs(a, "vm-c2") == POWER  # host level overrides global
    assert vm_privs(a, "vm-s2") == CONFIG


def test_union_of_folder_and_host_paths() -> None:
    a = access(perm(("folder", "F1"), CONFIG), perm(("host", "H1"), POWER))
    assert vm_privs(a, "vm-c1") == POWER | CONFIG
    assert vm_privs(a, "vm-c3") == CONFIG
    assert vm_privs(a, "vm-c2") == POWER


def test_no_access_on_a_folder_blocks_only_that_path() -> None:
    a = access(no_access(("folder", "F1")), perm(("host", "H1")))
    assert not a.sees_folder("F1")
    assert vm_privs(a, "vm-c1") == POWER  # still reached through the host path
    assert vm_privs(a, "vm-c3") is None  # H2 grants nothing


def test_vm_level_overrides_both_paths() -> None:
    a = access(perm(("folder", "F1")), perm(("vm", "vm-c1"), CONFIG))
    assert vm_privs(a, "vm-c1") == CONFIG


def test_r3_folder_grant_plus_no_access_on_one_vm_hides_it() -> None:
    a = access(perm(("folder", "F1")), perm(("host", "H1")), no_access(("vm", "vm-c1")))
    assert vm_privs(a, "vm-c1") is None
    assert vm_privs(a, "vm-c3") == POWER


def test_read_only_is_visible_without_privileges() -> None:
    a = access(perm(("cluster", "C1"), role_id=READ_ONLY_ROLE_ID))
    assert a.privileges(("cluster", "C1")) == frozenset()
    assert vm_privs(a, "vm-c1") == frozenset()
    assert not a.can("vm.power", ("host", "H1"))


# ---- groups ---------------------------------------------------------------------


def test_groups_at_the_same_level_combine() -> None:
    a = access(
        perm(("host", "H1"), POWER, group="db-team"),
        perm(("host", "H1"), CONFIG, group="ops"),
    )
    assert a.privileges(("host", "H1")) == POWER | CONFIG


def test_no_access_at_a_level_beats_other_groups_there() -> None:
    a = access(
        perm(("host", "H1"), POWER, group="db-team"),
        no_access(("host", "H1"), group="ops"),
    )
    assert a.privileges(("host", "H1")) is None


def test_superuser_role_gets_everything() -> None:
    a = Access(Principals(groups=("ADMINISTRATOR",)), (), Topology())
    assert a.all
    assert a.privileges(("host", "anything")) == ALL_PRIVILEGES
    assert vm_privs(a, "vm-c1") == ALL_PRIVILEGES


def test_only_the_admin_group_is_superuser() -> None:
    assert Principals(groups=("ops", "ADMINISTRATOR")).superuser
    assert not Principals(groups=("ops",)).superuser


# ---- SQL twin ---------------------------------------------------------------------


def _clause_matches(a: Access, vm) -> bool:
    """Evaluate vm_clause() against one VM, without a database."""
    vis = a._vis()  # noqa: SLF001 - white-box check of the SQL inputs
    if vis.all:
        return True
    if vm.id in vis.vm_allow:
        return True
    if vm.id in vis.vm_direct:
        return False
    return vm.host_id in vis.vm_hosts or (
        vm.folder_id is not None and vm.folder_id in vis.vm_folders
    )


@pytest.mark.parametrize("seed", range(40))
def test_vm_clause_agrees_with_vm_visible(seed: int) -> None:
    rnd = random.Random(seed)
    scopes = [
        GLOBAL,
        ("cluster", "C1"),
        ("host", "H1"),
        ("host", "H2"),
        ("host", "S1"),
        ("folder", "F1"),
        ("folder", "F2"),
        *(("vm", v) for v in VMS),
    ]
    rows = []
    for scope in rnd.sample(scopes, rnd.randint(1, 5)):
        if rnd.random() < 0.25:
            rows.append(no_access(scope, propagate=rnd.random() < 0.8))
        else:
            rows.append(perm(scope, propagate=rnd.random() < 0.8))
    a = access(*rows)
    for vm in VMS.values():
        assert _clause_matches(a, vm) == a.vm_visible(vm), (rows, vm.id)
