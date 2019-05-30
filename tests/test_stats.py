# -*- coding: utf-8 -*-
"""Tests for `adguardhome.stats`."""
import aiohttp
import pytest
from adguardhome import AdGuardHome
from adguardhome.exceptions import AdGuardHomeError


@pytest.mark.asyncio
async def test_dns_queries(event_loop, aresponses):
    """Test requesting AdGuard Home DNS query stats."""
    aresponses.add(
        "example.com:3000",
        "/control/stats",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"dns_queries": 666}',
        ),
    )
    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        result = await adguard.stats.dns_queries()
        assert result == 666


@pytest.mark.asyncio
async def test_blocked_filtering(event_loop, aresponses):
    """Test requesting AdGuard Home filtering stats."""
    aresponses.add(
        "example.com:3000",
        "/control/stats",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"blocked_filtering": 1337}',
        ),
    )
    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        result = await adguard.stats.blocked_filtering()
        assert result == 1337


@pytest.mark.asyncio
async def test_blocked_percentage(event_loop, aresponses):
    """Test requesting AdGuard Home filtering stats."""
    aresponses.add(
        "example.com:3000",
        "/control/stats",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"dns_queries": 100, "blocked_filtering": 25}',
        ),
    )
    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        result = await adguard.stats.blocked_percentage()
        assert result == 25.0


@pytest.mark.asyncio
async def test_replaced_safebrowsing(event_loop, aresponses):
    """Test requesting AdGuard Home safebrowsing stats."""
    aresponses.add(
        "example.com:3000",
        "/control/stats",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"replaced_safebrowsing": 42}',
        ),
    )
    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        result = await adguard.stats.replaced_safebrowsing()
        assert result == 42


@pytest.mark.asyncio
async def test_replaced_parental(event_loop, aresponses):
    """Test requesting AdGuard Home parental control stats."""
    aresponses.add(
        "example.com:3000",
        "/control/stats",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"replaced_parental": 13}',
        ),
    )
    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        result = await adguard.stats.replaced_parental()
        assert result == 13


@pytest.mark.asyncio
async def test_replaced_safesearch(event_loop, aresponses):
    """Test requesting AdGuard Home safe search enforcement stats."""
    aresponses.add(
        "example.com:3000",
        "/control/stats",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"replaced_safesearch": 18}',
        ),
    )
    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        result = await adguard.stats.replaced_safesearch()
        assert result == 18


@pytest.mark.asyncio
async def test_avg_processing_time(event_loop, aresponses):
    """Test requesting AdGuard Home DNS avarage processing time stats."""
    aresponses.add(
        "example.com:3000",
        "/control/stats",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"avg_processing_time": 3.14}',
        ),
    )
    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        result = await adguard.stats.avg_processing_time()
        assert result == 3.14


@pytest.mark.asyncio
async def test_period(event_loop, aresponses):
    """Test requesting AdGuard Home stats period."""
    aresponses.add(
        "example.com:3000",
        "/control/stats",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"stats_period": "24 hours"}',
        ),
    )

    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        result = await adguard.stats.period()
        assert result == "24 hours"


@pytest.mark.asyncio
async def test_reset(event_loop, aresponses):
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
        aresponses.Response(status=200, text="Not OK"),
    )

    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        result = await adguard.stats.reset()
        assert result
        with pytest.raises(AdGuardHomeError):
            await adguard.stats.reset()
