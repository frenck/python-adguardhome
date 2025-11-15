"""Tests for `adguardhome.safebrowsing`."""

import aiohttp
import pytest
from aresponses import ResponsesMockServer

from adguardhome import AdGuardHome
from adguardhome.exceptions import AdGuardHomeError


async def test_enabled(aresponses: ResponsesMockServer) -> None:
    """Test request of current AdGuard Home browsing security status."""
    aresponses.add(
        "example.com:3000",
        "/control/safebrowsing/status",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"enabled": true}',
        ),
    )
    aresponses.add(
        "example.com:3000",
        "/control/safebrowsing/status",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"enabled": false}',
        ),
    )
    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        enabled = await adguard.safebrowsing.enabled()
        assert enabled
        enabled = await adguard.safebrowsing.enabled()
        assert not enabled


async def test_enable(aresponses: ResponsesMockServer) -> None:
    """Test enabling AdGuard Home browsing security."""
    aresponses.add(
        "example.com:3000",
        "/control/safebrowsing/enable",
        "POST",
        aresponses.Response(status=200, text="OK"),
    )
    aresponses.add(
        "example.com:3000",
        "/control/safebrowsing/enable",
        "POST",
        aresponses.Response(status=400, text="NOT OK"),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        await adguard.safebrowsing.enable()
        with pytest.raises(AdGuardHomeError):
            await adguard.safebrowsing.enable()


async def test_disable(aresponses: ResponsesMockServer) -> None:
    """Test disabling AdGuard Home browsing security."""
    aresponses.add(
        "example.com:3000",
        "/control/safebrowsing/disable",
        "POST",
        aresponses.Response(status=200, text="OK"),
    )
    aresponses.add(
        "example.com:3000",
        "/control/safebrowsing/disable",
        "POST",
        aresponses.Response(status=400, text="NOT OK"),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        await adguard.safebrowsing.disable()
        with pytest.raises(AdGuardHomeError):
            await adguard.safebrowsing.disable()
