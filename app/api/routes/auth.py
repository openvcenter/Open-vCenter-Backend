from __future__ import annotations

from fastapi import APIRouter

from ...schemas import MeOut
from ...services.privileges import PRIVILEGES
from ..deps import CurrentIdentity, Scope

router = APIRouter(tags=["auth"])


@router.get("/me", response_model=MeOut)
async def me(identity: CurrentIdentity, scope: Scope) -> MeOut:
    user = identity.user
    global_privs = scope.privileges(("global", None)) or frozenset()
    return MeOut(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        roles=list(identity.principals.roles),
        groups=list(identity.principals.groups),
        superuser=scope.superuser,
        global_privileges=[p for p in PRIVILEGES if p in global_privs],
    )
