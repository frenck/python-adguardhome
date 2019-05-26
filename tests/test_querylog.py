# -*- coding: utf-8 -*-
"""Tests for `adguardhome.querylog`."""
import aiohttp
import pytest
from adguardhome import AdGuardHome
from adguardhome.exceptions import AdGuardHomeError


@pytest.mark.asyncio
async def test_enabled(event_loop, aresponses):
    """Test request of current AdGuard Home query log status."""
    aresponses.add(
        "example.com:3000",
        "/control/status",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"querylog_enabled": true}',
        ),
    )
    aresponses.add(
        "example.com:3000",
        "/control/status",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"querylog_enabled": false}',
        ),
    )
    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        enabled = await adguard.querylog.enabled()
        assert enabled
        enabled = await adguard.querylog.enabled()
        assert not enabled


@pytest.mark.asyncio
async def test_enable(event_loop, aresponses):
    """Test enabling AdGuard Home query log."""
    aresponses.add(
        "example.com:3000",
        "/control/querylog_enable",
        "POST",
        aresponses.Response(status=200, text="OK"),
    )
    aresponses.add(
        "example.com:3000",
        "/control/querylog_enable",
        "POST",
        aresponses.Response(status=200, text="NOT OK"),
    )

    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        result = await adguard.querylog.enable()
        assert result
        with pytest.raises(AdGuardHomeError):
            await adguard.querylog.enable()


@pytest.mark.asyncio
async def test_disable(event_loop, aresponses):
    """Test disabling AdGuard Home query log."""
    aresponses.add(
        "example.com:3000",
        "/control/querylog_disable",
        "POST",
        aresponses.Response(status=200, text="OK"),
    )
    aresponses.add(
        "example.com:3000",
        "/control/querylog_disable",
        "POST",
        aresponses.Response(status=200, text="NOT OK"),
    )

    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        result = await adguard.querylog.disable()
        assert result
        with pytest.raises(AdGuardHomeError):
            await adguard.querylog.disable()
