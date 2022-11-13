"""Tests for `adguardhome.blocked_services`."""

import aiohttp
import pytest

from adguardhome import AdGuardHome


@pytest.mark.asyncio
async def test_all_services_id(aresponses):
    """Test request of current AdGuard Home of all blockable services id."""
    aresponses.add(
        "example.com:3000",
        "/control/blocked_services/all",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"blocked_services": [{"id": "service_1"}]}',
        ),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        all_services = await adguard.blocked_services.all_services()
        assert len(all_services) == 1

        first_element = all_services[0]
        assert first_element["id"] == "service_1"


@pytest.mark.asyncio
async def test_all_services_name(aresponses):
    """Test request of current AdGuard Home of all blockable services name."""
    aresponses.add(
        "example.com:3000",
        "/control/blocked_services/all",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"blocked_services": [{"name": "Service 1"}]}',
        ),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        all_services = await adguard.blocked_services.all_services()
        assert len(all_services) == 1

        first_element = all_services[0]
        assert first_element["name"] == "Service 1"


@pytest.mark.asyncio
async def test_all_services_icon(aresponses):
    """Test request of current AdGuard Home of all blockable services icon."""
    aresponses.add(
        "example.com:3000",
        "/control/blocked_services/all",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"blocked_services": [{"icon_svg": "test_data"}]}',
        ),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        all_services = await adguard.blocked_services.all_services()
        assert len(all_services) == 1

        first_element = all_services[0]
        assert first_element["icon_svg"] == "test_data"


@pytest.mark.asyncio
async def test_set_blocked_services(aresponses):
    """Test request of current AdGuard Home setting blocked services ."""
    aresponses.add(
        "example.com:3000",
        "/control/blocked_services/set",
        "POST",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text="",
        ),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        response = await adguard.blocked_services.set_blocked_services(["service_1"])
        assert response is None


@pytest.mark.asyncio
async def test_list_currently_blocked(aresponses):
    """Test request of current AdGuard Home list_currently_blocked."""
    aresponses.add(
        "example.com:3000",
        "/control/blocked_services/list",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='["service_1", "service_2"]',
        ),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        blocked_services = await adguard.blocked_services.list_currently_blocked()

        assert len(blocked_services) == 2

        first_blocked = blocked_services[0]
        assert first_blocked == "service_1"

        second_blocked = blocked_services[1]
        assert second_blocked == "service_2"
