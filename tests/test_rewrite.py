"""Tests for `adguardhome.rewrite`."""

import aiohttp
import pytest
from aresponses import ResponsesMockServer

from adguardhome import AdGuardHome
from adguardhome.exceptions import AdGuardHomeError


@pytest.mark.asyncio
async def test_list(aresponses: ResponsesMockServer) -> None:
    """Test getting all DNS rewrite rules from AdGuard Home rewrite."""
    aresponses.add(
        "example.com:3000",
        "/control/rewrite/list",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='[{"domain": "*.example.com", "answer": "192.168.1.2"}, \
             {"domain": "*.example.com", "answer": "192.168.1.2"}]',
        ),
    )

    aresponses.add(
        "example.com:3000",
        "/control/rewrite/list",
        "GET",
        aresponses.Response(
            status=200, headers={"Content-Type": "application/json"}, text="[]"
        ),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        result = await adguard.rewrite.list()
        assert result == [
            {"domain": "*.example.com", "answer": "192.168.1.2"},
            {"domain": "*.example.com", "answer": "192.168.1.2"},
        ]
        result = await adguard.rewrite.list()
        assert result == []


@pytest.mark.asyncio
async def test_add(aresponses: ResponsesMockServer) -> None:
    """Test add new DNS rewrite to AdGuard rewrite."""
    aresponses.add(
        "example.com:3000",
        "/control/rewrite/add",
        "POST",
        aresponses.Response(status=200),
    )
    aresponses.add(
        "example.com:3000",
        "/control/rewrite/add",
        "POST",
        aresponses.Response(status=400, text="Bad Request"),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        await adguard.rewrite.add("*.example.com", "192.168.1.2")
        with pytest.raises(AdGuardHomeError):
            await adguard.rewrite.add("*.example.com", "192.168.1.2")


@pytest.mark.asyncio
async def test_remove(aresponses: ResponsesMockServer) -> None:
    """Test removing DNS rewrite from AdGuard rewrite."""
    aresponses.add(
        "example.com:3000",
        "/control/rewrite/delete",
        "POST",
        aresponses.Response(status=200),
    )
    aresponses.add(
        "example.com:3000",
        "/control/rewrite/delete",
        "POST",
        aresponses.Response(status=400, text="Bad Request"),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        await adguard.rewrite.delete("*.example.com", "192.168.1.2")
        with pytest.raises(AdGuardHomeError):
            await adguard.rewrite.delete("*.example.com", "192.168.1.2")
