"""Privilege catalog and role ids.

A privilege is the smallest unit of access ("power on a VM"); every mutating
operation needs exactly one. Reading needs none - any permission that is not
"No access" makes the object visible. The catalog lives in code: adding one is
a code change, and the built-in Administrator role picks it up automatically.
"""

from __future__ import annotations

# id -> (group, label). Order is the display order in the Roles editor.
PRIVILEGES: dict[str, tuple[str, str]] = {
    "vm.power": ("Virtual machine", "Power on / off, restart, pause"),
    "vm.console": ("Virtual machine", "Open console"),
    "vm.config": ("Virtual machine", "Edit settings, rename, tags, move to folder"),
    "vm.snapshot": ("Virtual machine", "Create, restore and remove checkpoints"),
    "vm.delete": ("Virtual machine", "Delete or remove from inventory"),
    "vm.migrate": ("Virtual machine", "Migrate between hosts or storage"),
    "vm.media": ("Virtual machine", "Mount and eject DVD / ISO"),
    # checked on the host / cluster / folder a VM lands in, never on a VM
    "vm.create": ("Host", "Create VMs (new, clone, deploy) and receive moved ones"),
    "host.maintenance": ("Host", "Suspend, drain, resume, restart"),
    "host.config": ("Host", "Edit host settings and VLANs"),
    "host.manage": ("Host", "Add, remove and move hosts, manage agents"),
    "host.console": ("Host", "Open host remote desktop"),
    "cluster.manage": ("Cluster", "Create, edit and delete clusters"),
    "folder.manage": ("Inventory", "Create, rename and delete folders"),
    "tag.manage": ("Inventory", "Manage the tag catalog"),
    "task.cancel": ("Operations", "Release VM locks"),
    "audit.read": ("Operations", "Read the audit log"),
    "settings.manage": ("Operations", "Manage global settings"),
    "rbac.manage": ("Security", "Manage roles and permissions"),
}

ALL_PRIVILEGES: frozenset[str] = frozenset(PRIVILEGES)

# Built-in roles: fixed ids (seeded by migration 0006), not editable. Their
# privileges are defined here, not in role_privileges.
ADMINISTRATOR_ROLE_ID = "00000000-0000-4000-8000-000000000001"
READ_ONLY_ROLE_ID = "00000000-0000-4000-8000-000000000002"
NO_ACCESS_ROLE_ID = "00000000-0000-4000-8000-000000000003"

BUILTIN_ROLE_PRIVILEGES: dict[str, frozenset[str]] = {
    ADMINISTRATOR_ROLE_ID: ALL_PRIVILEGES,
    READ_ONLY_ROLE_ID: frozenset(),
    NO_ACCESS_ROLE_ID: frozenset(),
}

PRINCIPAL_TYPES = ("role", "group")
# Coarsest first. A VM has two parents (its folder and its host), see rbac.py.
SCOPE_TYPES = ("global", "cluster", "host", "folder", "vm")
