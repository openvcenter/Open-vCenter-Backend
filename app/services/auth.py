from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..ids import new_id
from ..models import User

log = logging.getLogger(__name__)
_settings = get_settings()


async def _lookup(db: AsyncSession, email: str) -> User | None:
    return (
        await db.execute(select(User).where(User.email == email))
    ).scalar_one_or_none()


async def get_or_create_user(
    db: AsyncSession,
    *,
    email: str,
    display_name: str | None = None,
    groups: list[str] | None = None,
) -> User:
    user = await _lookup(db, email)

    if user is None:
        candidate = User(
            id=new_id(),
            email=email,
            display_name=display_name or email.split("@")[0],
            groups=groups or None,
        )
        try:
            async with db.begin_nested():  # SAVEPOINT - survives a lost create race
                db.add(candidate)
                await db.flush()
            user = candidate
            log.info("provisioned user %s", email)
        except IntegrityError:
            user = await _lookup(db, email)  # a concurrent request won - reuse it

    if user is None:  # pragma: no cover - the row must exist by now
        raise RuntimeError(f"could not get or create user {email}")

    if groups is not None:
        user.groups = groups

    return user


async def resolve_stub_user(db: AsyncSession) -> User:
    """Dev principal: one shared admin (member of the admin group)."""
    return await get_or_create_user(
        db, email=_settings.stub_user_email, groups=[_settings.admin_group]
    )
