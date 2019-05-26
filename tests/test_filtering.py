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
    aresponses.add(
        "example.com:3000",
        "/control/filtering/enable",
        "POST",
        aresponses.Response(status=200, text="OK"),
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/enable",
        "POST",
        aresponses.Response(status=200, text="NOT OK"),
    )

    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        result = await adguard.filtering.enable()
        assert result
        with pytest.raises(AdGuardHomeError):
            await adguard.filtering.enable()


@pytest.mark.asyncio
async def test_disable(event_loop, aresponses):
    """Test disabling AdGuard Home filtering."""
    aresponses.add(
        "example.com:3000",
        "/control/filtering/disable",
        "POST",
        aresponses.Response(status=200, text="OK"),
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/disable",
        "POST",
        aresponses.Response(status=200, text="NOT OK"),
    )

    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        result = await adguard.filtering.disable()
        assert result
        with pytest.raises(AdGuardHomeError):
            await adguard.filtering.disable()


@pytest.mark.asyncio
async def test_add_url(event_loop, aresponses):
    """Test add new filter subscription to AdGuard Home filtering."""
    aresponses.add(
        "example.com:3000",
        "/control/filtering/add_url",
        "POST",
        aresponses.Response(status=200, text="OK 12345 filters added"),
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/add_url",
        "POST",
        aresponses.Response(status=200, text="Invalid URL"),
    )

    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        result = await adguard.filtering.add_url("Example", "https://example.com/1.txt")
        assert result
        with pytest.raises(AdGuardHomeError):
            await adguard.filtering.add_url("Example", "https://example.com/1.txt")


@pytest.mark.asyncio
async def test_remove_url(event_loop, aresponses):
    """Test remove filter subscription from AdGuard Home filtering."""
    aresponses.add(
        "example.com:3000",
        "/control/filtering/remove_url",
        "POST",
        aresponses.Response(status=200, text="OK"),
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/remove_url",
        "POST",
        aresponses.Response(status=200, text="Invalid URL"),
    )

    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        result = await adguard.filtering.remove_url("https://example.com/1.txt")
        assert result
        with pytest.raises(AdGuardHomeError):
            await adguard.filtering.remove_url("https://example.com/1.txt")


@pytest.mark.asyncio
async def test_enable_url(event_loop, aresponses):
    """Test enabling filter subscription in AdGuard Home filtering."""
    aresponses.add(
        "example.com:3000",
        "/control/filtering/enable_url",
        "POST",
        aresponses.Response(status=200, text="OK"),
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/enable_url",
        "POST",
        aresponses.Response(status=200, text="Invalid URL"),
    )

    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        result = await adguard.filtering.enable_url("https://example.com/1.txt")
        assert result
        with pytest.raises(AdGuardHomeError):
            await adguard.filtering.enable_url("https://example.com/1.txt")


@pytest.mark.asyncio
async def test_disable_url(event_loop, aresponses):
    """Test enabling filter subscription in AdGuard Home filtering."""
    aresponses.add(
        "example.com:3000",
        "/control/filtering/disable_url",
        "POST",
        aresponses.Response(status=200, text="OK"),
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/disable_url",
        "POST",
        aresponses.Response(status=200, text="Invalid URL"),
    )

    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        result = await adguard.filtering.disable_url("https://example.com/1.txt")
        assert result
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
        result = await adguard.filtering.refresh(False)
        assert result
        result = await adguard.filtering.refresh(True)
        assert result
        with pytest.raises(AdGuardHomeError):
            await adguard.filtering.refresh(False)
