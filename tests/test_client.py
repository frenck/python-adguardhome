"""Tests for `adguardhome.client`"""

import json

import aiohttp
import pytest
from aresponses import ResponsesMockServer

from adguardhome import AdGuardHome
from adguardhome.client import AutoClient, Client, WhoisInfo


@pytest.mark.parametrize(
    "method", ["get_auto_clients", "get_clients", "get_supported_tags"]
)
async def test_empty_list(aresponses: ResponsesMockServer, method: str) -> None:
    """Test listing clients."""
    aresponses.add(
        "example.com:3000",
        "/control/clients",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text=json.dumps({"auto_clients": [], "clients": [], "supported_tags": []}),
        ),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        call = getattr(adguard.clients, method)
        assert await call() == []


async def test_get_auto_clients(aresponses: ResponsesMockServer) -> None:
    """Test listing auto clients."""
    aresponses.add(
        "example.com:3000",
        "/control/clients",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text=json.dumps(
                {
                    "auto_clients": [
                        {"ip": "192.0.2.1", "name": "otto", "source": "test"},
                        {
                            "ip": "192.0.2.3",
                            "name": "otto",
                            "source": "test",
                            "whois_info": {"type": "who knows?"},
                        },
                    ],
                    "clients": [],
                    "supported_tags": [],
                }
            ),
        ),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        output = await adguard.clients.get_auto_clients()
        assert (
            AutoClient(ip="192.0.2.1", name="otto", source="test", whois_info=None)
            in output
        )
        assert (
            AutoClient(
                ip="192.0.2.3",
                name="otto",
                source="test",
                whois_info=WhoisInfo(type="who knows?"),
            )
            in output
        )


async def test_get_clients(aresponses: ResponsesMockServer) -> None:
    """Test getting configured clients from AdGuard Home"""
    aresponses.add(
        "example.com:3000",
        "/control/clients",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text=json.dumps(
                {
                    "auto_clients": [],
                    "clients": [
                        {
                            "blocked_services": None,
                            "filtering_enabled": False,
                            "ids": ["192.0.2.1", "192.0.2.2"],
                            "name": "test",
                            "parental_enabled": True,
                            "safebrowsing_enabled": True,
                            "safesearch_enabled": True,
                            "tags": ["some tag"],
                            "upstreams": ["some upstream"],
                            "use_global_blocked_services": False,
                            "use_global_settings": False,
                        },
                    ],
                    "supported_tags": [],
                }
            ),
        ),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        output = await adguard.clients.get_clients()
        assert (
            Client(
                name="test",
                ids=["192.0.2.1", "192.0.2.2"],
                filtering_enabled=False,
                parental_enabled=True,
                safebrowsing_enabled=True,
                safesearch_enabled=True,
                use_global_blocked_services=False,
                use_global_settings=False,
                blocked_services=None,
                tags=["some tag"],
                upstreams=["some upstream"],
            )
            in output
        )
