"""Tests for `adguardhome.blocked_services`."""

from datetime import timedelta
from typing import Any

from aiointercept import CallbackResult, aiointercept
from syrupy.assertion import SnapshotAssertion
from yarl import URL

from adguardhome import AdGuardHome, BlockedServicesConfig, DayRange, Schedule

from .conftest import FixtureLoader

URL_BASE = "http://example.com:3000/control/blocked_services"
URL_ALL = f"{URL_BASE}/all"
URL_GET = f"{URL_BASE}/get"
URL_UPDATE = f"{URL_BASE}/update"


def expect_json(expected: Any) -> Any:
    """Return a callback asserting the JSON body of the request."""

    def callback(_url: URL, **kwargs: Any) -> CallbackResult:
        assert kwargs["json"] == expected
        return CallbackResult(status=200, body="OK\n", content_type="text/plain")

    return callback


async def test_get(
    responses: aiointercept,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
    snapshot: SnapshotAssertion,
) -> None:
    """Test the available services are parsed into models."""
    responses.get(URL_ALL, status=200, payload=load_fixture("blocked_services_all"))

    available = await adguard.blocked_services.get()

    assert available == snapshot
    assert [service.id for service in available.services] == [
        "youtube",
        "tiktok",
        "steam",
    ]
    assert available.services[0].rules == ("||youtube.com^", "||ytimg.com^")
    assert available.services[0].group_id == "streaming"
    assert len(available.groups) == 3


async def test_config(
    responses: aiointercept,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
) -> None:
    """Test the blocked services and their pause schedule are parsed."""
    data = load_fixture("blocked_services_get")
    responses.get(URL_GET, status=200, payload=data)

    config = await adguard.blocked_services.config()

    assert config == BlockedServicesConfig(
        blocked=("youtube", "tiktok"),
        schedule=Schedule(
            time_zone="Europe/Amsterdam",
            sat=DayRange(start=timedelta(hours=10), end=timedelta(hours=18)),
        ),
    )
    assert config.to_dict() == data


async def test_set_config_without_schedule(
    responses: aiointercept, adguard: AdGuardHome
) -> None:
    """Test a config without a schedule leaves it out, so blocking never pauses."""
    responses.put(URL_UPDATE, callback=expect_json({"ids": ["steam"]}))

    await adguard.blocked_services.set_config(BlockedServicesConfig(blocked=("steam",)))


async def test_block(
    responses: aiointercept,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
) -> None:
    """Test blocking adds new services, keeping the others and the schedule."""
    data = load_fixture("blocked_services_get")
    responses.get(URL_GET, status=200, payload=data)
    responses.put(
        URL_UPDATE,
        callback=expect_json(data | {"ids": ["youtube", "tiktok", "steam"]}),
    )

    await adguard.blocked_services.block("steam", "youtube")


async def test_unblock(
    responses: aiointercept,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
) -> None:
    """Test unblocking removes services, keeping the others and the schedule."""
    data = load_fixture("blocked_services_get")
    responses.get(URL_GET, status=200, payload=data)
    responses.put(URL_UPDATE, callback=expect_json(data | {"ids": ["youtube"]}))

    await adguard.blocked_services.unblock("tiktok", "steam")
