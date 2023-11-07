"""Tests for `adguardhome.parental`."""
import aiohttp
import pytest
from aresponses import ResponsesMockServer

from adguardhome import AdGuardHome
from adguardhome.exceptions import AdGuardHomeError


async def test_enabled(aresponses: ResponsesMockServer) -> None:
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
    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        enabled = await adguard.parental.enabled()
        assert enabled
        enabled = await adguard.parental.enabled()
        assert not enabled


async def test_enable(aresponses: ResponsesMockServer) -> None:
    """Test enabling AdGuard Home parental control."""
    # Handle to run asserts on request in
    aresponses.add(
        "example.com:3000",
        "/control/parental/enable",
        "POST",
        aresponses.Response(status=200, text="OK"),
    )
    aresponses.add(
        "example.com:3000",
        "/control/parental/enable",
        "POST",
        aresponses.Response(status=400, text="NOT OK"),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        await adguard.parental.enable()
        with pytest.raises(AdGuardHomeError):
            await adguard.parental.enable()


async def test_disable(aresponses: ResponsesMockServer) -> None:
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
        aresponses.Response(status=400, text="NOT OK"),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        await adguard.parental.disable()
        with pytest.raises(AdGuardHomeError):
            await adguard.parental.disable()
