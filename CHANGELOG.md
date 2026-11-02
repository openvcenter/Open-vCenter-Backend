# Changelog

All notable changes to ovc-backend. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/). Each version is a git tag
(`0.1.1`, no `v` prefix) with a matching GitHub Release and container image
(`ghcr.io/openvcenter/ovc-backend:<version>`). See README "Releasing".

## [Unreleased]

## [0.3.0] - 2026-11-02

### Added

- Role-based access control. Privileges (`vm.power`, `vm.console`,
  `host.maintenance`, `rbac.manage`, …) make up roles; a permission grants a
  role to an identity-provider group on global, a cluster, a host, a folder or
  a VM, optionally propagating to what is below. A VM's own permissions
  override the rest, otherwise it gets the union of its folder and its host;
  the most specific level wins and No access blocks a path. Built-in roles
  Administrator, Read-only and No access, plus editable sample roles.
- Every mutating route checks its privilege (VM actions through
  `VM_ACTION_PRIVILEGES`). Lists show only granted objects; the host / cluster
  of a visible VM stays readable. Creating, renaming, moving and removing hosts
  and clusters needs the privilege globally, and a folder is managed from its
  cluster or host - a permission on an object covers what is inside it, not the
  object itself. A delegate can't grant a role with privileges they lack.
- API: `/rbac/catalog`, `/roles` (CRUD + clone), `/permissions` (CRUD, direct
  and inherited), `/rbac/groups`, `/me/privileges` (batched), `/rbac/effective`
  (why a group may do what). Role and permission changes are audited.
- `GET /vms/{id}/console` (`vm.console`) and `GET /hosts/{id}/console`
  (`host.console`): where a console connects; the frontend tunnel no longer
  takes an address from the browser.
- Permissions follow deletes of clusters, hosts, folders and VMs, plus an hourly
  orphan sweeper in the worker.
- Migration 0006: `roles`, `role_privileges`, `permissions`; `users.groups`
  replaces `users.roles`; `scope_grants` is dropped.

### Changed

- The user's groups are read from the token at `OVC_OIDC_GROUPS_CLAIM`
  (default `resource_access.${client_id}.roles`, the Keycloak client roles;
  `groups` for Keycloak groups, Entra ID, Okta). It replaces
  `OVC_OIDC_ROLES_CLAIM`. Members of `OVC_ADMIN_GROUP` (default
  `ADMINISTRATOR`) are superusers; it replaces `OVC_ADMIN_ROLE`.
- `GET /me` returns `groups`, `superuser` and `globalPrivileges` instead of
  `roles` and `scopes`.

## [0.2.1] - 2026-10-17

### Changed

- The project moved to the openvcenter GitHub organization: images are now
  published as `ghcr.io/openvcenter/ovc-backend`, and the README shows the new
  Open vCenter logo. No code changes.

## [0.2.0] - 2026-10-03

### Added

- Audit log: every change made through the API (VM create / clone / delete /
  power and management actions / folder move / tags, folders, clusters, host
  membership and actions, VLANs, tags, agent binaries, forced lock releases) is
  recorded with who, when, the target's name and a before/after diff.
  Agent-task events start `pending` and the worker settles them to the task's
  outcome. VMs that vanish from a host's inventory (deleted outside OVC) are
  recorded as system events. `GET /audit-events` (admin only, filters, cursor
  pagination). Kept `OVC_AUDIT_RETENTION_DAYS` (default 365, `0` = forever).
  Migration 0005. Run the API and the worker from the same release - the
  worker is what settles event outcomes.

## [0.1.1] - 2026-10-03

### Added

- VM tags: a global catalog of categories and tags with colours from a fixed
  10-name palette (`/tag-categories`, `/tags`, admin-only writes), and
  `PUT /vms/{id}/tags` for anyone who can see the VM. A VM holds at most one
  tag per category. Migrations 0002 and 0003.
- Host actions (`POST /hosts/{id}/actions/{action}`): Failover Cluster node
  pause / resume (with drain and fallback), host restart, forced hardware
  and inventory refresh. Disruptive actions are admin-only.
- VM guest OS and console thumbnails from the agent's `vm_inventory`:
  `guestOs` on VMs and `GET /vms/{id}/thumbnail` (JPEG, `X-Captured-At`).
  Migration 0004.
- Richer host hardware: NIC driver / firmware / link details, vSwitch and
  SET teaming info, Fibre Channel HBAs.
- The app version (OpenAPI `info.version`) comes from `pyproject.toml`.

### Changed

- VM placement rules on create, clone and storage move: clustered hosts
  accept only Cluster Shared Volumes; standalone hosts reject `C:` unless it
  holds the Hyper-V default VM path.
- Migrating a VM between cluster nodes requires High Availability.
- Python 3.14 and updated dependencies.

### Fixed

- Agent binary upload accepts only `.exe` files.

## [0.1.0] - 2026-09-20

First public release.

[Unreleased]: https://github.com/openvcenter/Open-vCenter-Backend/compare/0.3.0...HEAD
[0.3.0]: https://github.com/openvcenter/Open-vCenter-Backend/compare/0.2.1...0.3.0
[0.2.1]: https://github.com/openvcenter/Open-vCenter-Backend/compare/0.2.0...0.2.1
[0.2.0]: https://github.com/openvcenter/Open-vCenter-Backend/compare/0.1.1...0.2.0
[0.1.1]: https://github.com/openvcenter/Open-vCenter-Backend/compare/0.1.0...0.1.1
[0.1.0]: https://github.com/openvcenter/Open-vCenter-Backend/releases/tag/0.1.0
