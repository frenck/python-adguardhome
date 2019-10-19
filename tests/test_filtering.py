# -*- coding: utf-8 -*-
"""Tests for `adguardhome.filtering`."""
import aiohttp
import pytest
from adguardhome import AdGuardHome
from adguardhome.exceptions import AdGuardHomeError


@pytest.mark.asyncio
async def test_enabled(event_loop, aresponses):
    """Test request of current AdGuard Home filter status."""
    aresponses.add(
        "example.com:3000",
        "/control/filtering/status",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"enabled": true}',
        ),
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/status",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"enabled": false}',
        ),
    )
    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        enabled = await adguard.filtering.enabled()
        assert enabled
        enabled = await adguard.filtering.enabled()
        assert not enabled


@pytest.mark.asyncio
async def test_enable(event_loop, aresponses):
    """Test enabling AdGuard Home filtering."""

    async def response_handler(request):
        data = await request.json()
        assert data == {"enabled": True, "interval": 1}
        return aresponses.Response(status=200)

    aresponses.add(
        "example.com:3000",
        "/control/filtering/status",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"interval": 1}',
        ),
    )
    aresponses.add(
        "example.com:3000", "/control/filtering_config", "POST", response_handler
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/status",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"interval": 1}',
        ),
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering_config",
        "POST",
        aresponses.Response(status=500),
    )

    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        await adguard.filtering.enable()
        with pytest.raises(AdGuardHomeError):
            await adguard.filtering.enable()


@pytest.mark.asyncio
async def test_disable(event_loop, aresponses):
    """Test disabling AdGuard Home filtering."""

    async def response_handler(request):
        data = await request.json()
        assert data == {"enabled": False, "interval": 1}
        return aresponses.Response(status=200)

    aresponses.add(
        "example.com:3000",
        "/control/filtering/status",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"interval": 1}',
        ),
    )
    aresponses.add(
        "example.com:3000", "/control/filtering_config", "POST", response_handler
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/status",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"interval": 1}',
        ),
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering_config",
        "POST",
        aresponses.Response(status=400),
    )

    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        await adguard.filtering.disable()
        with pytest.raises(AdGuardHomeError):
            await adguard.filtering.disable()


@pytest.mark.asyncio
async def test_interval(event_loop, aresponses):
    """Test interval settings of the AdGuard Home filtering."""

    async def response_handler(request):
        data = await request.json()
        assert data == {"enabled": True, "interval": 1}
        return aresponses.Response(status=200)

    aresponses.add(
        "example.com:3000",
        "/control/filtering/status",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"interval": 7}',
        ),
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/status",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"enabled": true}',
        ),
    )
    aresponses.add(
        "example.com:3000", "/control/filtering_config", "POST", response_handler
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/status",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"enabled": true}',
        ),
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering_config",
        "POST",
        aresponses.Response(status=400),
    )

    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        interval = await adguard.filtering.interval()
        assert interval == 7
        interval = await adguard.filtering.interval(interval=1)
        assert interval == 1
        with pytest.raises(AdGuardHomeError):
            await adguard.filtering.interval(interval=1)


@pytest.mark.asyncio
async def test_rules_count(event_loop, aresponses):
    """Test getting rules count of the AdGuard Home filtering."""
    aresponses.add(
        "example.com:3000",
        "/control/filtering/status",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"filters": [{"rulesCount": 99}, {"rulesCount": 1}]}',
        ),
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/status",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"filters": []}',
        ),
    )

    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        result = await adguard.filtering.rules_count()
        assert result == 100
        result = await adguard.filtering.rules_count()
        assert result == 0


@pytest.mark.asyncio
async def test_add_url(event_loop, aresponses):
    """Test add new filter subscription to AdGuard Home filtering."""
    # Handle to run asserts on request in
    async def response_handler(request):
        data = await request.json()
        assert data == {"name": "Example", "url": "https://example.com/1.txt"}
        return aresponses.Response(status=200, text="OK 12345 filters added")

    aresponses.add(
        "example.com:3000", "/control/filtering/add_url", "POST", response_handler
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/add_url",
        "POST",
        aresponses.Response(status=200, text="Invalid URL"),
    )

    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        await adguard.filtering.add_url("Example", "https://example.com/1.txt")
        with pytest.raises(AdGuardHomeError):
            await adguard.filtering.add_url("Example", "https://example.com/1.txt")


@pytest.mark.asyncio
async def test_remove_url(event_loop, aresponses):
    """Test remove filter subscription from AdGuard Home filtering."""
    # Handle to run asserts on request in
    async def response_handler(request):
        data = await request.json()
        assert data == {"url": "https://example.com/1.txt"}
        return aresponses.Response(status=200, text="OK")

    aresponses.add(
        "example.com:3000", "/control/filtering/remove_url", "POST", response_handler
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/remove_url",
        "POST",
        aresponses.Response(status=200, text="Invalid URL"),
    )

    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        await adguard.filtering.remove_url("https://example.com/1.txt")
        with pytest.raises(AdGuardHomeError):
            await adguard.filtering.remove_url("https://example.com/1.txt")


@pytest.mark.asyncio
async def test_enable_url(event_loop, aresponses):
    """Test enabling filter subscription in AdGuard Home filtering."""
    # Handle to run asserts on request in
    async def response_handler(request):
        data = await request.text()
        assert data == "url=https://example.com/1.txt"
        return aresponses.Response(status=200, text="OK")

    aresponses.add(
        "example.com:3000", "/control/filtering/enable_url", "POST", response_handler
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/enable_url",
        "POST",
        aresponses.Response(status=200, text="Invalid URL"),
    )

    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        await adguard.filtering.enable_url("https://example.com/1.txt")
        with pytest.raises(AdGuardHomeError):
            await adguard.filtering.enable_url("https://example.com/1.txt")


@pytest.mark.asyncio
async def test_disable_url(event_loop, aresponses):
    """Test enabling filter subscription in AdGuard Home filtering."""
    # Handle to run asserts on request in
    async def response_handler(request):
        data = await request.text()
        assert data == "url=https://example.com/1.txt"
        return aresponses.Response(status=200, text="OK")

    aresponses.add(
        "example.com:3000", "/control/filtering/disable_url", "POST", response_handler
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/disable_url",
        "POST",
        aresponses.Response(status=200, text="Invalid URL"),
    )

    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        await adguard.filtering.disable_url("https://example.com/1.txt")
        with pytest.raises(AdGuardHomeError):
            await adguard.filtering.disable_url("https://example.com/1.txt")


@pytest.mark.asyncio
async def test_refresh(event_loop, aresponses):
    """Test enabling filter subscription in AdGuard Home filtering."""
    aresponses.add(
        "example.com:3000",
        "/control/filtering/refresh?force=false",
        "POST",
        aresponses.Response(status=200, text="OK"),
        match_querystring=True,
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/refresh?force=true",
        "POST",
        aresponses.Response(status=200, text="OK"),
        match_querystring=True,
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/refresh?force=false",
        "POST",
        aresponses.Response(status=200, text="Not OK"),
        match_querystring=True,
    )

    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        await adguard.filtering.refresh(False)
        await adguard.filtering.refresh(True)
        with pytest.raises(AdGuardHomeError):
            await adguard.filtering.refresh(False)
