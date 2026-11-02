from __future__ import annotations

from app.task_timeouts import DiskSize, task_timeout_seconds, task_timeouts


def test_quick_kind_leaves_the_agent_default() -> None:
    t = task_timeouts("vm_start", {})
    assert t.agent is None
    assert t.backend == task_timeout_seconds("vm_start") == 300


def test_long_kind_without_disks() -> None:
    t = task_timeouts("vm_shutdown", {})
    assert t == (600, 900)


def test_vm_create_adds_a_budget_per_disk() -> None:
    t = task_timeouts(
        "vm_create",
        {
            "disks": [
                {"type": "Fixed", "size_gb": 300},  # 3000s
                {"type": "Fixed", "size_gb": 5},  # minimum 120s
                {"type": "Dynamic", "size_gb": 2000},  # 60s
            ]
        },
    )
    assert t.agent == 1800 + 3000 + 120 + 60
    assert t.backend == t.agent + 300


def test_vm_edit_counts_added_and_expanded_disks() -> None:
    t = task_timeouts(
        "vm_edit",
        {
            "add_disk": {"type": "Fixed", "size_gb": 100},  # single object
            "edit_disk": [{"path": "D:\\a.vhdx", "size_gb": 50}],  # assumed Fixed
        },
    )
    assert t.agent == 1800 + 1000 + 500


def test_bad_disk_entries_are_ignored() -> None:
    t = task_timeouts("vm_edit", {"add_disk": [{"size_gb": "x"}, "nope"]})
    assert t.agent == 1800 + 60


def test_backend_only_kind() -> None:
    t = task_timeouts("host_update_agent")
    assert t == (None, 1800)


GIB = 1024**3


def test_vm_move_and_rename_copy_the_used_bytes() -> None:
    disks = [DiskSize(200 * GIB, 100 * GIB, fixed=False), DiskSize(50 * GIB, 50 * GIB, True)]
    assert task_timeouts("vm_move", {}, disks=disks).agent == 1800 + 1500
    assert task_timeouts("vm_rename", {}, disks=disks).agent == 1800 + 1500


def test_vm_export_template_copies_then_converts_fixed_disks() -> None:
    disks = [DiskSize(200 * GIB, 100 * GIB, fixed=False), DiskSize(50 * GIB, 50 * GIB, True)]
    # export 150 GB, then convert the 50 GB Fixed disk
    assert task_timeouts("vm_export_template", {}, disks=disks).agent == 1800 + 1500 + 500


def test_vm_clone_from_vm_copies_twice() -> None:
    disks = [DiskSize(200 * GIB, 100 * GIB, fixed=False)]
    t = task_timeouts("vm_clone", {"clone_type": "imported"}, disks=disks)
    assert t.agent == 1800 + 2 * 1000


def test_vm_clone_from_template_copies_and_expands() -> None:
    disks = [DiskSize(300 * GIB, 20 * GIB, fixed=False)]
    params = {"clone_type": "exported", "expand_disks": True}
    assert task_timeouts("vm_clone", params, disks=disks).agent == 1800 + 200 + 3000
    params["expand_disks"] = False
    assert task_timeouts("vm_clone", params, disks=disks).agent == 1800 + 200


def test_disks_do_not_affect_other_kinds() -> None:
    disks = [DiskSize(300 * GIB, 300 * GIB, fixed=True)]
    assert task_timeouts("vm_start", {}, disks=disks).agent is None
    assert task_timeouts("vm_shutdown", {}, disks=disks).agent == 600
