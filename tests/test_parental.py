# -*- coding: utf-8 -*-
"""Tests for `adguardhome.parental`."""
import aiohttp
import pytest
from adguardhome import AdGuardHome
from adguardhome.exceptions import AdGuardHomeError


@pytest.mark.asyncio
async def test_enabled(event_loop, aresponses):
    """Test request of current AdGuard Home parental control status."""
    aresponses.add(
        "example.com:3000",
        "/control/parental/status",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"enabled": true}',
        ),
    )
    aresponses.add(
        "example.com:3000",
        "/control/parental/status",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"enabled": false}',
        ),
    )
    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        enabled = await adguard.parental.enabled()
        assert enabled
        enabled = await adguard.parental.enabled()
        assert not enabled


@pytest.mark.asyncio
async def test_enable(event_loop, aresponses):
    """Test enabling AdGuard Home parental control."""
    # Handle to run asserts on request in
    async def response_handler(request):
        data = await request.text()
        assert data == "sensitivity=TEEN"
        return aresponses.Response(status=200, text="OK")

    aresponses.add(
        "example.com:3000", "/control/parental/enable", "POST", response_handler
    )
    aresponses.add(
        "example.com:3000",
        "/control/parental/enable",
        "POST",
        aresponses.Response(status=200, text="NOT OK"),
    )

    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        result = await adguard.parental.enable()
        assert result
        with pytest.raises(AdGuardHomeError):
            await adguard.parental.enable()


@pytest.mark.asyncio
async def test_disable(event_loop, aresponses):
    """Test disabling AdGuard Home parental control."""
    aresponses.add(
        "example.com:3000",
        "/control/parental/disable",
        "POST",
        aresponses.Response(status=200, text="OK"),
    )
    aresponses.add(
        "example.com:3000",
        "/control/parental/disable",
        "POST",
        aresponses.Response(status=200, text="NOT OK"),
    )

    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        result = await adguard.parental.disable()
        assert result
        with pytest.raises(AdGuardHomeError):
            await adguard.parental.disable()
