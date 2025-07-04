"""Tests for `adguardhome.update`."""

import aiohttp
import pytest
from aresponses import ResponsesMockServer

from adguardhome import AdGuardHome
from adguardhome.exceptions import AdGuardHomeError


async def test_update_available(aresponses: ResponsesMockServer) -> None:
    """Test request of current AdGuard Home latest available update."""
    aresponses.add(
        "example.com:3000",
        "/control/version.json",
        "POST",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text=(
                '{"new_version":"v0.107.59",'
                '"announcement":"AdGuard Home v0.107.59 is now available!",'
                '"announcement_url":"https://github.com/AdguardTeam/AdGuardHome/releases/tag/v0.107.59",'
                '"can_autoupdate":true,"disabled":false}'
            ),
        ),
    )
    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        available_update = await adguard.update.update_available()
        assert available_update
        assert (
            available_update.announcement == "AdGuard Home v0.107.59 is now available!"
        )
        assert (
            available_update.announcement_url
            == "https://github.com/AdguardTeam/AdGuardHome/releases/tag/v0.107.59"
        )
        assert available_update.can_autoupdate
        assert available_update.disabled is False
        assert available_update.new_version == "v0.107.59"


async def test_begin_update(aresponses: ResponsesMockServer) -> None:
    """Test beginning AdGuard Home automatic upgrade."""
    # Handle to run asserts on request in
    aresponses.add(
        "example.com:3000",
        "/control/update",
        "POST",
        aresponses.Response(status=200, text="OK"),
    )
    aresponses.add(
        "example.com:3000",
        "/control/update",
        "POST",
        aresponses.Response(status=400, text="NOT OK"),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        await adguard.update.begin_update()
        with pytest.raises(AdGuardHomeError):
            await adguard.update.begin_update()
