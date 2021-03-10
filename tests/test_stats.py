"""Tests for `adguardhome.stats`."""
import aiohttp
import pytest

from adguardhome import AdGuardHome
from adguardhome.exceptions import AdGuardHomeError


@pytest.mark.asyncio
async def test_dns_queries(aresponses):
    """Test requesting AdGuard Home number of DNS query stats."""
    aresponses.add(
        "example.com:3000",
        "/control/stats",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"num_dns_queries": 666}',
        ),
    )
    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        result = await adguard.stats.dns_queries()
        assert result == 666


@pytest.mark.asyncio
async def test_blocked_filtering(aresponses):
    """Test requesting AdGuard Home filtering stats."""
    aresponses.add(
        "example.com:3000",
        "/control/stats",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"num_blocked_filtering": 1337}',
        ),
    )
    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        result = await adguard.stats.blocked_filtering()
        assert result == 1337


@pytest.mark.asyncio
async def test_blocked_percentage(aresponses):
    """Test requesting AdGuard Home filtering stats."""
    aresponses.add(
        "example.com:3000",
        "/control/stats",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"num_dns_queries": 100, "num_blocked_filtering": 25}',
        ),
    )
    aresponses.add(
        "example.com:3000",
        "/control/stats",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"num_dns_queries": 0, "num_blocked_filtering": 25}',
        ),
    )
    aresponses.add(
        "example.com:3000",
        "/control/stats",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"num_dns_queries": 100, "num_blocked_filtering": 0}',
        ),
    )
    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        result = await adguard.stats.blocked_percentage()
        assert result == 25.0
        result = await adguard.stats.blocked_percentage()
        assert result == 0.0
        result = await adguard.stats.blocked_percentage()
        assert result == 0.0


@pytest.mark.asyncio
async def test_replaced_safebrowsing(aresponses):
    """Test requesting AdGuard Home safebrowsing stats."""
    aresponses.add(
        "example.com:3000",
        "/control/stats",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"num_replaced_safebrowsing": 42}',
        ),
    )
    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        result = await adguard.stats.replaced_safebrowsing()
        assert result == 42


@pytest.mark.asyncio
async def test_replaced_parental(aresponses):
    """Test requesting AdGuard Home parental control stats."""
    aresponses.add(
        "example.com:3000",
        "/control/stats",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"num_replaced_parental": 13}',
        ),
    )
    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        result = await adguard.stats.replaced_parental()
        assert result == 13


@pytest.mark.asyncio
async def test_replaced_safesearch(aresponses):
    """Test requesting AdGuard Home safe search enforcement stats."""
    aresponses.add(
        "example.com:3000",
        "/control/stats",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"num_replaced_safesearch": 18}',
        ),
    )
    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        result = await adguard.stats.replaced_safesearch()
        assert result == 18


@pytest.mark.asyncio
async def test_avg_processing_time(aresponses):
    """Test requesting AdGuard Home DNS average processing time stats."""
    aresponses.add(
        "example.com:3000",
        "/control/stats",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"avg_processing_time": 0.03141}',
        ),
    )
    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        result = await adguard.stats.avg_processing_time()
        assert result == 31.41


@pytest.mark.asyncio
async def test_period(aresponses):
    """Test requesting AdGuard Home stats period."""
    aresponses.add(
        "example.com:3000",
        "/control/stats_info",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"interval": 7}',
        ),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        result = await adguard.stats.period()
        assert result == 7


@pytest.mark.asyncio
async def test_reset(aresponses):
    """Test resetting all AdGuard Home stats."""
    aresponses.add(
        "example.com:3000",
        "/control/stats_reset",
        "POST",
        aresponses.Response(status=200, text="OK"),
    )
    aresponses.add(
        "example.com:3000",
        "/control/stats_reset",
        "POST",
        aresponses.Response(status=400, text="Not OK"),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        await adguard.stats.reset()
        with pytest.raises(AdGuardHomeError):
            await adguard.stats.reset()
