"""Tests for `adguardhome.client`."""

import pytest
from aioresponses import aioresponses
from syrupy.assertion import SnapshotAssertion

from adguardhome import AdGuardHome, AutoClient

from .conftest import FixtureLoader

URL_CLIENTS = "http://example.com:3000/control/clients"


async def test_get_auto_clients(
    responses: aioresponses,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
) -> None:
    """Test listing automatically discovered clients."""
    responses.get(URL_CLIENTS, status=200, payload=load_fixture("clients"))

    result = await adguard.clients.get_auto_clients()

    assert len(result) == 2
    assert result[0] == AutoClient(
        ip_address="192.168.1.10",
        name="phone",
        source="rdns",
    )
    assert result[1].whois_info == {"orgname": "Local Network"}


async def test_get_auto_clients_snapshot(
    responses: aioresponses,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
    snapshot: SnapshotAssertion,
) -> None:
    """Test auto_clients parsing matches snapshot."""
    responses.get(URL_CLIENTS, status=200, payload=load_fixture("clients"))
    assert await adguard.clients.get_auto_clients() == snapshot


async def test_get_clients(
    responses: aioresponses,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
) -> None:
    """Test listing configured clients."""
    responses.get(URL_CLIENTS, status=200, payload=load_fixture("clients"))

    result = await adguard.clients.get_clients()

    assert len(result) == 1
    client = result[0]
    assert client.name == "Kids devices"
    assert client.ids == ["192.168.1.30", "192.168.1.31"]
    assert client.filtering_enabled is True
    assert client.parental_enabled is True
    assert client.use_global_settings is False
    assert client.blocked_services == ["youtube"]
    assert client.tags == ["device_tablet"]


async def test_get_clients_snapshot(
    responses: aioresponses,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
    snapshot: SnapshotAssertion,
) -> None:
    """Test clients parsing matches snapshot."""
    responses.get(URL_CLIENTS, status=200, payload=load_fixture("clients"))
    assert await adguard.clients.get_clients() == snapshot


async def test_get_clients_ignores_unknown_fields(
    responses: aioresponses,
    adguard: AdGuardHome,
) -> None:
    """Test that unknown fields from the API are silently ignored."""
    responses.get(
        URL_CLIENTS,
        status=200,
        payload={
            "auto_clients": [],
            "clients": [
                {
                    "name": "test",
                    "ids": ["192.168.1.1"],
                    "use_global_settings": True,
                    "some_future_field": "should be ignored",
                    "another_unknown": 42,
                },
            ],
            "supported_tags": [],
        },
    )

    result = await adguard.clients.get_clients()
    assert len(result) == 1
    assert result[0].name == "test"


async def test_get_supported_tags(
    responses: aioresponses,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
) -> None:
    """Test listing supported client tags."""
    responses.get(URL_CLIENTS, status=200, payload=load_fixture("clients"))

    result = await adguard.clients.get_supported_tags()

    assert len(result) == 10
    assert "device_tablet" in result
    assert "user_child" in result


@pytest.mark.parametrize(
    ("method", "payload"),
    [
        (
            "get_auto_clients",
            {"auto_clients": [], "clients": [], "supported_tags": []},
        ),
        (
            "get_clients",
            {"auto_clients": [], "clients": [], "supported_tags": []},
        ),
        (
            "get_supported_tags",
            {"auto_clients": [], "clients": [], "supported_tags": []},
        ),
        (
            "get_auto_clients",
            {"auto_clients": None, "clients": None, "supported_tags": None},
        ),
        (
            "get_clients",
            {"auto_clients": None, "clients": None, "supported_tags": None},
        ),
        (
            "get_supported_tags",
            {"auto_clients": None, "clients": None, "supported_tags": None},
        ),
    ],
)
async def test_empty_response(
    responses: aioresponses,
    adguard: AdGuardHome,
    method: str,
    payload: dict[str, list[object] | None],
) -> None:
    """Test all methods return empty lists when no data is present."""
    responses.get(URL_CLIENTS, status=200, payload=payload)
    assert await getattr(adguard.clients, method)() == []
