# -*- coding: utf-8 -*-
"""Tests for `adguardhome.safesearch`."""
import aiohttp
import pytest
from adguardhome import AdGuardHome
from adguardhome.exceptions import AdGuardHomeError


@pytest.mark.asyncio
async def test_enabled(event_loop, aresponses):
    """Test request of current AdGuard Home safe search enforcing status."""
    aresponses.add(
        "example.com:3000",
        "/control/safesearch/status",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"enabled": true}',
        ),
    )
    aresponses.add(
        "example.com:3000",
        "/control/safesearch/status",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"enabled": false}',
        ),
    )
    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        enabled = await adguard.safesearch.enabled()
        assert enabled
        enabled = await adguard.safesearch.enabled()
        assert not enabled


@pytest.mark.asyncio
async def test_enable(event_loop, aresponses):
    """Test enabling AdGuard Home safe search enforcing."""
    aresponses.add(
        "example.com:3000",
        "/control/safesearch/enable",
        "POST",
        aresponses.Response(status=200, text="OK"),
    )
    aresponses.add(
        "example.com:3000",
        "/control/safesearch/enable",
        "POST",
        aresponses.Response(status=200, text="NOT OK"),
    )

    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        await adguard.safesearch.enable()
        with pytest.raises(AdGuardHomeError):
            await adguard.safesearch.enable()


@pytest.mark.asyncio
async def test_disable(event_loop, aresponses):
    """Test disabling AdGuard Home safe search enforcing."""
    aresponses.add(
        "example.com:3000",
        "/control/safesearch/disable",
        "POST",
        aresponses.Response(status=200, text="OK"),
    )
    aresponses.add(
        "example.com:3000",
        "/control/safesearch/disable",
        "POST",
        aresponses.Response(status=200, text="NOT OK"),
    )

    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        await adguard.safesearch.disable()
        with pytest.raises(AdGuardHomeError):
            await adguard.safesearch.disable()
