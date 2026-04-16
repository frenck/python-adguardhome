"""Tests for `adguardhome.stats`."""

from typing import Any

import pytest
from aioresponses import aioresponses

from adguardhome import AdGuardHome
from adguardhome.exceptions import AdGuardHomeError

from .conftest import FixtureLoader

URL_STATS = "http://example.com:3000/control/stats"
URL_STATS_INFO = "http://example.com:3000/control/stats_info"
URL_STATS_RESET = "http://example.com:3000/control/stats_reset"


async def test_dns_queries(
    responses: aioresponses,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
) -> None:
    """Test requesting total number of DNS queries."""
    responses.get(URL_STATS, status=200, payload=load_fixture("stats"))
    assert await adguard.stats.dns_queries() == 666


async def test_blocked_filtering(
    responses: aioresponses,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
) -> None:
    """Test requesting number of DNS queries blocked by filtering."""
    responses.get(URL_STATS, status=200, payload=load_fixture("stats"))
    assert await adguard.stats.blocked_filtering() == 1337


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ({"num_dns_queries": 100, "num_blocked_filtering": 25}, 25.0),
        ({"num_dns_queries": 0, "num_blocked_filtering": 25}, 0.0),
        ({"num_dns_queries": 100, "num_blocked_filtering": 0}, 0.0),
    ],
)
async def test_blocked_percentage(
    responses: aioresponses,
    adguard: AdGuardHome,
    payload: dict[str, Any],
    expected: float,
) -> None:
    """Test the blocked percentage ratio calculation."""
    responses.get(URL_STATS, status=200, payload=payload)
    assert await adguard.stats.blocked_percentage() == expected


async def test_replaced_safebrowsing(
    responses: aioresponses,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
) -> None:
    """Test requesting number of pages blocked by safe browsing."""
    responses.get(URL_STATS, status=200, payload=load_fixture("stats"))
    assert await adguard.stats.replaced_safebrowsing() == 42


async def test_replaced_parental(
    responses: aioresponses,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
) -> None:
    """Test requesting number of pages blocked by parental control."""
    responses.get(URL_STATS, status=200, payload=load_fixture("stats"))
    assert await adguard.stats.replaced_parental() == 13


async def test_replaced_safesearch(
    responses: aioresponses,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
) -> None:
    """Test requesting number of enforced safe searches."""
    responses.get(URL_STATS, status=200, payload=load_fixture("stats"))
    assert await adguard.stats.replaced_safesearch() == 18


async def test_avg_processing_time(
    responses: aioresponses,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
) -> None:
    """Test requesting average DNS query processing time in milliseconds."""
    responses.get(URL_STATS, status=200, payload=load_fixture("stats"))
    assert await adguard.stats.avg_processing_time() == 31.41


async def test_period(responses: aioresponses, adguard: AdGuardHome) -> None:
    """Test requesting the stats retention period."""
    responses.get(URL_STATS_INFO, status=200, payload={"interval": 7})
    assert await adguard.stats.period() == 7


async def test_reset(responses: aioresponses, adguard: AdGuardHome) -> None:
    """Test resetting all stats."""
    responses.post(URL_STATS_RESET, status=200, body="OK", content_type="text/plain")
    await adguard.stats.reset()


@pytest.mark.parametrize("status", [400, 500])
async def test_reset_error(
    responses: aioresponses,
    adguard: AdGuardHome,
    status: int,
) -> None:
    """Test resetting stats fails on HTTP error."""
    responses.post(
        URL_STATS_RESET, status=status, body="Not OK", content_type="text/plain"
    )
    with pytest.raises(AdGuardHomeError):
        await adguard.stats.reset()
