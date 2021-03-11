"""Tests for `adguardhome.querylog`."""
import aiohttp
import pytest

from adguardhome import AdGuardHome
from adguardhome.exceptions import AdGuardHomeError


@pytest.mark.asyncio
async def test_enabled(aresponses):
    """Test request of current AdGuard Home query log status."""
    aresponses.add(
        "example.com:3000",
        "/control/querylog_info",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"enabled": true,"interval": 1}',
        ),
    )
    aresponses.add(
        "example.com:3000",
        "/control/querylog_info",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"enabled": false,"interval": 1}',
        ),
    )
    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        enabled = await adguard.querylog.enabled()
        enabled = await adguard.querylog.enabled()
        assert not enabled


@pytest.mark.asyncio
async def test_enable(aresponses):
    """Test enabling AdGuard Home query log."""

    async def response_handler(request):
        """Response handler for this test."""
        data = await request.json()
        assert data == {"enabled": True, "interval": 1}
        return aresponses.Response(status=200)

    aresponses.add(
        "example.com:3000",
        "/control/querylog_info",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"interval": 1}',
        ),
    )
    aresponses.add(
        "example.com:3000", "/control/querylog_config", "POST", response_handler
    )
    aresponses.add(
        "example.com:3000",
        "/control/querylog_info",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"interval": 1}',
        ),
    )
    aresponses.add(
        "example.com:3000",
        "/control/querylog_config",
        "POST",
        aresponses.Response(status=500),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        await adguard.querylog.enable()
        with pytest.raises(AdGuardHomeError):
            await adguard.querylog.enable()


@pytest.mark.asyncio
async def test_disable(aresponses):
    """Test disabling AdGuard Home query log."""

    async def response_handler(request):
        """Response handler for this test."""
        data = await request.json()
        assert data == {"enabled": False, "interval": 1}
        return aresponses.Response(status=200)

    aresponses.add(
        "example.com:3000",
        "/control/querylog_info",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"interval": 1}',
        ),
    )
    aresponses.add(
        "example.com:3000", "/control/querylog_config", "POST", response_handler
    )
    aresponses.add(
        "example.com:3000",
        "/control/querylog_info",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"interval": 1}',
        ),
    )
    aresponses.add(
        "example.com:3000",
        "/control/querylog_config",
        "POST",
        aresponses.Response(status=500),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        await adguard.querylog.disable()
        with pytest.raises(AdGuardHomeError):
            await adguard.querylog.disable()


@pytest.mark.asyncio
async def test_interval(aresponses):
    """Test interval settings of the AdGuard Home filtering."""

    async def response_handler(request):
        """Response handler for this test."""
        data = await request.json()
        assert data == {"enabled": True, "interval": 1}
        return aresponses.Response(status=200)

    aresponses.add(
        "example.com:3000",
        "/control/querylog_info",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"interval": 7}',
        ),
    )
    aresponses.add(
        "example.com:3000",
        "/control/querylog_info",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"enabled": true}',
        ),
    )
    aresponses.add(
        "example.com:3000", "/control/querylog_config", "POST", response_handler
    )
    aresponses.add(
        "example.com:3000",
        "/control/querylog_info",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"enabled": true}',
        ),
    )
    aresponses.add(
        "example.com:3000",
        "/control/querylog_config",
        "POST",
        aresponses.Response(status=400),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        interval = await adguard.querylog.interval()
        assert interval == 7
        interval = await adguard.querylog.interval(interval=1)
        assert interval == 1
        with pytest.raises(AdGuardHomeError):
            await adguard.querylog.interval(interval=1)
