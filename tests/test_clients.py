"""Tests for `adguardhome.clients`."""

from dataclasses import replace
from datetime import timedelta
from typing import Any

import pytest
from aiointercept import CallbackResult, aiointercept
from syrupy.assertion import SnapshotAssertion
from yarl import URL

from adguardhome import (
    AdGuardHome,
    AdGuardHomeError,
    Client,
    Clients,
    DayRange,
    SafeSearchConfig,
)

from .conftest import FixtureLoader

URL_BASE = "http://example.com:3000/control/clients"
URL_ADD = f"{URL_BASE}/add"
URL_UPDATE = f"{URL_BASE}/update"
URL_DELETE = f"{URL_BASE}/delete"
URL_SEARCH = f"{URL_BASE}/search"


def expect_json(expected: Any, payload: Any = None) -> Any:
    """Return a callback asserting the JSON body of the request."""

    def callback(_url: URL, **kwargs: Any) -> CallbackResult:
        assert kwargs["json"] == expected
        if payload is not None:
            return CallbackResult(status=200, payload=payload)
        return CallbackResult(status=200, body="OK\n", content_type="text/plain")

    return callback


async def test_get(
    responses: aiointercept,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
    snapshot: SnapshotAssertion,
) -> None:
    """Test all clients are parsed into a model with a single request."""
    responses.get(URL_BASE, status=200, payload=load_fixture("clients"))

    clients = await adguard.clients.get()

    assert clients == snapshot
    assert len(clients.configured) == 1
    assert len(clients.runtime) == 2
    assert "user_child" in clients.supported_tags


async def test_get_configured_client(
    responses: aiointercept,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
) -> None:
    """Test a configured client carries its own settings and schedule."""
    responses.get(URL_BASE, status=200, payload=load_fixture("clients"))

    client = (await adguard.clients.get()).configured[0]

    assert client.name == "Kids devices"
    assert not client.use_global_settings
    assert client.safe_search.enabled
    assert not client.safe_search.youtube
    assert client.upstreams == ()
    assert client.blocked_services == ("youtube", "tiktok")

    schedule = client.blocked_services_schedule
    assert schedule is not None
    assert schedule.time_zone == "Europe/Amsterdam"
    assert schedule.sat == DayRange(start=timedelta(hours=10), end=timedelta(hours=18))
    assert schedule.sun == DayRange(start=timedelta(hours=10), end=timedelta(hours=24))
    assert schedule.mon is None


async def test_get_runtime_client(
    responses: aiointercept,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
) -> None:
    """Test a runtime client carries where AdGuard Home found it."""
    responses.get(URL_BASE, status=200, payload=load_fixture("clients"))

    phone, isp = (await adguard.clients.get()).runtime

    assert phone.ip_address == "192.168.1.10"
    assert phone.source == "rDNS"
    assert phone.whois_info == {}
    assert isp.whois_info == {"country": "NL", "orgname": "Example ISP"}


async def test_get_empty(responses: aiointercept, adguard: AdGuardHome) -> None:
    """Test AdGuard Home without any clients, which sends nulls."""
    responses.get(
        URL_BASE,
        status=200,
        payload={"clients": None, "auto_clients": None, "supported_tags": None},
    )

    assert await adguard.clients.get() == Clients()


def test_client_serializes_without_deprecated_fields(
    load_fixture: FixtureLoader,
) -> None:
    """Test a client sends `safe_search`, never the deprecated boolean."""
    data = load_fixture("clients")["clients"][0]
    client = Client.from_api(data)

    serialized = client.to_dict()

    assert "safesearch_enabled" not in serialized
    assert serialized["safe_search"] == data["safe_search"]
    assert serialized["blocked_services_schedule"] == data["blocked_services_schedule"]
    assert Client.from_api(serialized) == client


async def test_add(responses: aiointercept, adguard: AdGuardHome) -> None:
    """Test adding a client with only the settings that matter to it."""
    responses.post(
        URL_ADD,
        callback=expect_json(
            {
                "name": "Printer",
                "ids": ["192.168.1.50"],
                "tags": [],
                "use_global_settings": False,
                "filtering_enabled": True,
                "parental_enabled": False,
                "safebrowsing_enabled": False,
                "safe_search": {
                    "enabled": False,
                    "bing": False,
                    "duckduckgo": False,
                    "ecosia": False,
                    "google": False,
                    "pixabay": False,
                    "yandex": False,
                    "youtube": False,
                },
                "use_global_blocked_services": True,
                "blocked_services": [],
                "upstreams": [],
                "upstreams_cache_enabled": False,
                "upstreams_cache_size": 0,
                "ignore_querylog": True,
                "ignore_statistics": False,
            }
        ),
    )

    await adguard.clients.add(
        Client(
            name="Printer",
            ids=("192.168.1.50",),
            use_global_settings=False,
            filtering_enabled=True,
            ignore_querylog=True,
        )
    )


async def test_update(
    responses: aiointercept,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
) -> None:
    """Test updating a client by its current name, also renaming it."""
    responses.get(URL_BASE, status=200, payload=load_fixture("clients"))
    client = (await adguard.clients.get()).configured[0]
    renamed = replace(
        client,
        name="Kids",
        safe_search=SafeSearchConfig(enabled=True, google=True, youtube=True),
    )

    responses.post(
        URL_UPDATE,
        callback=expect_json({"name": "Kids devices", "data": renamed.to_dict()}),
    )

    await adguard.clients.update("Kids devices", renamed)


async def test_remove(responses: aiointercept, adguard: AdGuardHome) -> None:
    """Test removing a client by its name."""
    responses.post(URL_DELETE, callback=expect_json({"name": "Printer"}))

    await adguard.clients.remove("Printer")


async def test_search(
    responses: aiointercept,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
) -> None:
    """Test searching returns the applied settings per ID, also unknown ones."""
    responses.post(
        URL_SEARCH,
        callback=expect_json(
            {"clients": [{"id": "192.168.1.30"}, {"id": "203.0.113.7"}]},
            payload=load_fixture("clients_search"),
        ),
    )

    results = await adguard.clients.search("192.168.1.30", "203.0.113.7")

    assert list(results) == ["192.168.1.30", "203.0.113.7"]

    kids = results["192.168.1.30"]
    assert kids.name == "Kids devices"
    assert not kids.disallowed

    unknown = results["203.0.113.7"]
    assert unknown.name == ""
    assert unknown.disallowed
    assert unknown.disallowed_rule == "203.0.113.0/24"
    assert unknown.whois_info == {"country": "NL"}
    assert unknown.ignore_querylog is False


@pytest.mark.parametrize("payload", [{"192.168.1.30": {}}, ["not an object"]])
async def test_search_unexpected_response(
    responses: aiointercept, adguard: AdGuardHome, payload: Any
) -> None:
    """Test a search response that is not a list of objects raises an error."""
    responses.post(URL_SEARCH, status=200, payload=payload)

    with pytest.raises(AdGuardHomeError):
        await adguard.clients.search("192.168.1.30")
