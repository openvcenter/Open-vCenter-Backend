"""Console targets. The frontend's Guacamole tunnel asks the backend where to
connect instead of trusting a hostname from the browser, so the privilege
check (`vm.console` / `host.console`) and the address come from one place."""

from __future__ import annotations

from ..api.errors import ApiError
from ..models import Host

RDP_PORT = 3389
# Hyper-V VMConnect (RDP + preconnection blob carrying the VM GUID)
HYPERV_CONSOLE_PORT = 2179


def console_target(host: Host, *, port: int, vm_guid: str | None = None) -> dict:
    address = host.fqdn or host.ip_address
    if not address:
        raise ApiError(
            "CONSOLE_UNAVAILABLE",
            f"Host '{host.name}' has not reported an FQDN or IP address yet",
            status_code=409,
        )
    return {"hostname": address, "port": port, "vm_guid": vm_guid}
