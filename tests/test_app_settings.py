"""GET / PATCH /settings: no DB - a fake session holds the one settings row."""

from __future__ import annotations

import httpx
import pytest

from app.api.deps import Identity, get_identity, get_scope
from app.api.errors import ApiError
from app.db import get_session
from app.ids import new_id
from app.main import app
from app.models import APP_SETTINGS_ID, AppSettings, AuditEvent, User
from app.services import app_settings as app_settings_service
from app.services.app_settings import (
    METRICS_INTERVAL_OPTIONS,
    METRICS_RETENTION_OPTIONS,
    check_metrics_interval,
    check_metrics_retention,
)
from app.services.privileges import READ_ONLY_ROLE_ID
from app.services.rbac import GLOBAL, Access, PermRow, Principals, Topology


class FakeSession:
    def __init__(self) -> None:
        self.settings = AppSettings(
            id=APP_SETTINGS_ID,
            metrics_retention_seconds=3600,
            metrics_interval_seconds=300,
            vm_console_non_admin_access=False,
        )
        self.added: list[object] = []
        self.host_short_ids: list[str] = []

    async def get(self, model, oid):
        return self.settings if model is AppSettings else None

    def add(self, obj) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        pass

    async def execute(self, stmt):
        ids = self.host_short_ids

        class _Result:
            def scalars(self):
                return iter(ids)

        return _Result()


def _access(*privileges: str, role_id: str | None = None) -> Access:
    row = PermRow(
        id=new_id(),
        group_id="ops",
        role_id=role_id or new_id(),
        role_name="test",
        scope_type=GLOBAL[0],
        scope_id=GLOBAL[1],
        propagate=True,
        privileges=frozenset(privileges),
    )
    return Access(Principals(groups=("ops",)), [row], Topology())


@pytest.fixture
def session() -> FakeSession:
    return FakeSession()


@pytest.fixture
def client_as(session):
    async def fake_session():
        yield session

    def make(access: Access) -> httpx.AsyncClient:
        user = User(id="u-1", email="ops@lab", display_name="Ops")
        app.dependency_overrides[get_session] = fake_session
        app.dependency_overrides[get_identity] = lambda: Identity(user, access.principals)
        app.dependency_overrides[get_scope] = lambda: access
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")

    yield make
    app.dependency_overrides.clear()


@pytest.fixture
def sent(monkeypatch) -> list[tuple[str, int]]:
    calls: list[tuple[str, int]] = []

    async def fake_send(host_ref: str, seconds: int) -> None:
        calls.append((host_ref, seconds))

    monkeypatch.setattr("app.api.routes.settings.send_metrics_config", fake_send)
    return calls


@pytest.mark.parametrize("seconds", METRICS_RETENTION_OPTIONS)
def test_valid_metrics_retention(seconds: int) -> None:
    assert check_metrics_retention(seconds) == seconds


@pytest.mark.parametrize("seconds", [0, -1, 60, 7200, 604801])
def test_invalid_metrics_retention(seconds: int) -> None:
    with pytest.raises(ApiError) as exc:
        check_metrics_retention(seconds)
    assert exc.value.code == "INVALID"
    assert exc.value.status_code == 400


@pytest.mark.parametrize("seconds", METRICS_INTERVAL_OPTIONS)
def test_valid_metrics_interval(seconds: int) -> None:
    assert check_metrics_interval(seconds) == seconds


@pytest.mark.parametrize("seconds", [0, 5, 45, 3600])
def test_invalid_metrics_interval(seconds: int) -> None:
    with pytest.raises(ApiError) as exc:
        check_metrics_interval(seconds)
    assert exc.value.code == "INVALID"


async def test_any_user_reads_settings(client_as) -> None:
    async with client_as(_access(role_id=READ_ONLY_ROLE_ID)) as client:
        resp = await client.get("/api/settings")
    assert resp.status_code == 200, resp.text
    assert resp.json() == {
        "metricsRetentionSeconds": 3600,
        "metricsRetentionOptions": list(METRICS_RETENTION_OPTIONS),
        "metricsIntervalSeconds": 300,
        "metricsIntervalOptions": list(METRICS_INTERVAL_OPTIONS),
        "vmConsoleNonAdminAccess": False,
    }


async def test_patch_needs_settings_manage(client_as, session) -> None:
    async with client_as(_access("rbac.manage")) as client:
        resp = await client.patch("/api/settings", json={"metricsRetentionSeconds": 86400})
    assert resp.status_code == 403, resp.text
    assert session.settings.metrics_retention_seconds == 3600


async def test_patch_rejects_a_retention_outside_the_presets(client_as, session) -> None:
    async with client_as(_access("settings.manage")) as client:
        resp = await client.patch("/api/settings", json={"metricsRetentionSeconds": 7200})
    assert resp.status_code == 400, resp.text
    assert resp.json()["error"]["code"] == "INVALID"
    assert session.settings.metrics_retention_seconds == 3600


async def test_patch_updates_and_audits_the_changed_fields(client_as, session, sent) -> None:
    async with client_as(_access("settings.manage")) as client:
        resp = await client.patch(
            "/api/settings",
            json={"metricsRetentionSeconds": 86400, "vmConsoleNonAdminAccess": False},
        )
    assert resp.status_code == 200, resp.text
    assert resp.json()["metricsRetentionSeconds"] == 86400
    [event] = [e for e in session.added if isinstance(e, AuditEvent)]
    assert event.action == "settings.update"
    assert event.target_type == "settings"
    assert event.details == {
        "before": {"metricsRetentionSeconds": 3600},
        "after": {"metricsRetentionSeconds": 86400},
    }
    assert sent == []  # interval unchanged: nothing pushed to the agents


async def test_patch_interval_pushes_it_to_every_agent(client_as, session, sent) -> None:
    session.host_short_ids = ["h1", "h2"]
    async with client_as(_access("settings.manage")) as client:
        resp = await client.patch("/api/settings", json={"metricsIntervalSeconds": 60})
    assert resp.status_code == 200, resp.text
    assert session.settings.metrics_interval_seconds == 60
    assert sent == [("h1", 60), ("h2", 60)]


async def test_patch_rejects_an_interval_outside_the_presets(client_as, session, sent) -> None:
    async with client_as(_access("settings.manage")) as client:
        resp = await client.patch("/api/settings", json={"metricsIntervalSeconds": 45})
    assert resp.status_code == 400, resp.text
    assert session.settings.metrics_interval_seconds == 300
    assert sent == []


async def test_send_metrics_config_publishes_the_request(monkeypatch) -> None:
    published = []

    async def fake_publish(host_ref, request):
        published.append((host_ref, request))

    monkeypatch.setattr(app_settings_service, "publish_request", fake_publish)
    await app_settings_service.send_metrics_config("h1", 120)
    [(host_ref, request)] = published
    assert host_ref == "h1"
    assert request.function == "set_metrics_config"
    assert request.params == {"interval_seconds": 120}


async def test_patch_without_changes_records_nothing(client_as, session) -> None:
    async with client_as(_access("settings.manage")) as client:
        resp = await client.patch("/api/settings", json={"vmConsoleNonAdminAccess": False})
    assert resp.status_code == 200, resp.text
    assert session.added == []
