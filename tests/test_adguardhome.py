"""Tests for `adguardhome.adguardhome`."""

import asyncio
from unittest.mock import patch

import aiohttp
import pytest
from aresponses import Response, ResponsesMockServer

from adguardhome import AdGuardHome
from adguardhome.exceptions import AdGuardHomeConnectionError, AdGuardHomeError


async def test_json_request(aresponses: ResponsesMockServer) -> None:
    """Test JSON response is handled correctly."""
    aresponses.add(
        "example.com:3000",
        "/",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"status": "ok"}',
        ),
    )
    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        response = await adguard.request("/")
        assert response["status"] == "ok"
        await adguard.close()


async def test_authenticated_request(aresponses: ResponsesMockServer) -> None:
    """Test JSON response is handled correctly."""
    aresponses.add(
        "example.com:3000",
        "/",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"status": "ok"}',
        ),
    )
    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome(
            "example.com",
            username="frenck",
            password="zerocool",  # noqa: S106
            session=session,
        )
        response = await adguard.request("/")
        assert response["status"] == "ok"


async def test_text_request(aresponses: ResponsesMockServer) -> None:
    """Test non JSON response is handled correctly."""
    aresponses.add(
        "example.com:3000", "/", "GET", aresponses.Response(status=200, text="OK")
    )
    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        response = await adguard.request("/")
        assert response == {"message": "OK"}


async def test_internal_session(aresponses: ResponsesMockServer) -> None:
    """Test JSON response is handled correctly."""
    aresponses.add(
        "example.com:3000",
        "/",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"status": "ok"}',
        ),
    )
    async with AdGuardHome("example.com") as adguard:
        response = await adguard.request("/")
        assert response["status"] == "ok"


async def test_post_request(aresponses: ResponsesMockServer) -> None:
    """Test POST requests are handled correctly."""
    aresponses.add(
        "example.com:3000", "/", "POST", aresponses.Response(status=200, text="OK")
    )
    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        response = await adguard.request("/", method="POST")
        assert response == {"message": "OK"}


async def test_request_port(aresponses: ResponsesMockServer) -> None:
    """Test AdGuard Home running on non-standard port."""
    aresponses.add(
        "example.com:3333",
        "/",
        "GET",
        aresponses.Response(text="OMG PUPPIES!", status=200),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", port=3333, session=session)
        response = await adguard.request("/")
        assert response == {"message": "OMG PUPPIES!"}


async def test_request_base_path(aresponses: ResponsesMockServer) -> None:
    """Test AdGuard Home running on different base path."""
    aresponses.add(
        "example.com:3000",
        "/admin/status",
        "GET",
        aresponses.Response(text="OMG PUPPIES!", status=200),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", base_path="/admin", session=session)
        response = await adguard.request("status")
        assert response == {"message": "OMG PUPPIES!"}


async def test_timeout(aresponses: ResponsesMockServer) -> None:
    """Test request timeout from AdGuard Home."""

    # Faking a timeout by sleeping
    async def response_handler(_: aiohttp.ClientResponse) -> Response:
        """Response handler for this test."""
        await asyncio.sleep(2)
        return aresponses.Response(body="Goodmorning!")

    aresponses.add("example.com:3000", "/", "GET", response_handler)

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session, request_timeout=1)
        with pytest.raises(AdGuardHomeConnectionError):
            assert await adguard.request("/")


async def test_client_error() -> None:
    """Test request client error from AdGuard Home."""
    # Faking a timeout by sleeping
    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        with patch.object(
            session, "request", side_effect=aiohttp.ClientError
        ), pytest.raises(AdGuardHomeConnectionError):
            assert await adguard.request("/")


async def test_http_error400(aresponses: ResponsesMockServer) -> None:
    """Test HTTP 404 response handling."""
    aresponses.add(
        "example.com:3000",
        "/",
        "GET",
        aresponses.Response(text="OMG PUPPIES!", status=404),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        with pytest.raises(AdGuardHomeError):
            assert await adguard.request("/")


async def test_http_error500(aresponses: ResponsesMockServer) -> None:
    """Test HTTP 500 response handling."""
    aresponses.add(
        "example.com:3000",
        "/",
        "GET",
        aresponses.Response(
            body=b'{"status":"nok"}',
            status=500,
            headers={"Content-Type": "application/json"},
        ),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        with pytest.raises(AdGuardHomeError):
            assert await adguard.request("/")


async def test_protection_enabled(aresponses: ResponsesMockServer) -> None:
    """Test request of current AdGuard Home protection status."""
    aresponses.add(
        "example.com:3000",
        "/control/status",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"protection_enabled": true}',
        ),
    )
    aresponses.add(
        "example.com:3000",
        "/control/status",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"protection_enabled": false}',
        ),
    )
    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        enabled = await adguard.protection_enabled()
        assert enabled
        enabled = await adguard.protection_enabled()
        assert not enabled


async def test_enable_protection(aresponses: ResponsesMockServer) -> None:
    """Test enabling AdGuard Home protection."""
    aresponses.add(
        "example.com:3000",
        "/control/protection",
        "POST",
        aresponses.Response(status=200),
    )
    aresponses.add(
        "example.com:3000",
        "/control/protection",
        "POST",
        aresponses.Response(status=400),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        await adguard.enable_protection()
        with pytest.raises(AdGuardHomeError):
            await adguard.enable_protection()


async def test_disable_protection(aresponses: ResponsesMockServer) -> None:
    """Test disabling AdGuard Home protection."""
    aresponses.add(
        "example.com:3000",
        "/control/protection",
        "POST",
        aresponses.Response(status=200),
    )
    aresponses.add(
        "example.com:3000",
        "/control/protection",
        "POST",
        aresponses.Response(status=500),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        await adguard.disable_protection()
        with pytest.raises(AdGuardHomeError):
            await adguard.disable_protection()


async def test_version(aresponses: ResponsesMockServer) -> None:
    """Test requesting AdGuard Home instance version."""
    aresponses.add(
        "example.com:3000",
        "/control/status",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"version": "1.1"}',
        ),
    )
    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        version = await adguard.version()
        assert version == "1.1"
