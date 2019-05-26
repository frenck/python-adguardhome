# -*- coding: utf-8 -*-
"""Tests for `adguardhome.adguardhome`."""
import asyncio

import aiohttp
import pytest
from adguardhome import AdGuardHome
from adguardhome.exceptions import AdGuardHomeConnectionError, AdGuardHomeError


@pytest.mark.asyncio
async def test_json_request(event_loop, aresponses):
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
    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        response = await adguard._request("/")
        assert response["status"] == "ok"


@pytest.mark.asyncio
async def test_authenticated_request(event_loop, aresponses):
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
    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome(
            "example.com",
            username="frenck",
            password="zerocool",
            session=session,
            loop=event_loop,
        )
        response = await adguard._request("/")
        assert response["status"] == "ok"


@pytest.mark.asyncio
async def test_text_request(event_loop, aresponses):
    """Test non JSON response is handled correctly."""
    aresponses.add(
        "example.com:3000", "/", "GET", aresponses.Response(status=200, text="OK")
    )
    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        response = await adguard._request("/")
        assert response == "OK"


@pytest.mark.asyncio
async def test_internal_session(event_loop, aresponses):
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
    async with AdGuardHome("example.com", loop=event_loop) as adguard:
        response = await adguard._request("/")
        assert response["status"] == "ok"


@pytest.mark.asyncio
async def test_internal_eventloop(aresponses):
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
        response = await adguard._request("/")
        assert response["status"] == "ok"


@pytest.mark.asyncio
async def test_post_request(event_loop, aresponses):
    """Test POST requests are handled correctly."""
    aresponses.add(
        "example.com:3000", "/", "POST", aresponses.Response(status=200, text="OK")
    )
    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        response = await adguard._request("/", method="POST")
        assert response == "OK"


@pytest.mark.asyncio
async def test_request_port(event_loop, aresponses):
    """Test AdGuard Home running on non-standard port."""
    aresponses.add(
        "example.com:3333",
        "/",
        "GET",
        aresponses.Response(text="OMG PUPPIES!", status=200),
    )

    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome(
            "example.com", port=3333, session=session, loop=event_loop
        )
        response = await adguard._request("/")
        assert response == "OMG PUPPIES!"


@pytest.mark.asyncio
async def test_request_base_path(event_loop, aresponses):
    """Test AdGuard Home running on different base path."""
    aresponses.add(
        "example.com:3000",
        "/admin/status",
        "GET",
        aresponses.Response(text="OMG PUPPIES!", status=200),
    )

    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome(
            "example.com", base_path="/admin", session=session, loop=event_loop
        )
        response = await adguard._request("status")
        assert response == "OMG PUPPIES!"


@pytest.mark.asyncio
async def test_timeout(event_loop, aresponses):
    """Test request timeout from AdGuard Home."""
    # Faking a timeout by sleeping
    async def response_handler(_):
        await asyncio.sleep(2)
        return aresponses.Response(body="Goodmorning!")

    aresponses.add("example.com:3000", "/", "GET", response_handler)

    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome(
            "example.com", session=session, loop=event_loop, request_timeout=1
        )
        with pytest.raises(AdGuardHomeConnectionError):
            assert await adguard._request("/")


@pytest.mark.asyncio
async def test_http_error400(event_loop, aresponses):
    """Test HTTP 404 response handling."""
    aresponses.add(
        "example.com:3000",
        "/",
        "GET",
        aresponses.Response(text="OMG PUPPIES!", status=404),
    )

    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        with pytest.raises(AdGuardHomeError):
            assert await adguard._request("/")


@pytest.mark.asyncio
async def test_http_error500(event_loop, aresponses):
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

    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        with pytest.raises(AdGuardHomeError):
            assert await adguard._request("/")


@pytest.mark.asyncio
async def test_protection_enabled(event_loop, aresponses):
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
    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        enabled = await adguard.protection_enabled()
        assert enabled
        enabled = await adguard.protection_enabled()
        assert not enabled


@pytest.mark.asyncio
async def test_enable_protection(event_loop, aresponses):
    """Test enabling AdGuard Home protection."""
    aresponses.add(
        "example.com:3000",
        "/control/enable_protection",
        "POST",
        aresponses.Response(status=200, text="OK"),
    )
    aresponses.add(
        "example.com:3000",
        "/control/enable_protection",
        "POST",
        aresponses.Response(status=200, text="NOT OK"),
    )

    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        result = await adguard.enable_protection()
        assert result
        with pytest.raises(AdGuardHomeError):
            await adguard.enable_protection()


@pytest.mark.asyncio
async def test_disable_protection(event_loop, aresponses):
    """Test disabling AdGuard Home protection."""
    aresponses.add(
        "example.com:3000",
        "/control/disable_protection",
        "POST",
        aresponses.Response(status=200, text="OK"),
    )
    aresponses.add(
        "example.com:3000",
        "/control/disable_protection",
        "POST",
        aresponses.Response(status=200, text="NOT OK"),
    )

    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        result = await adguard.disable_protection()
        assert result
        with pytest.raises(AdGuardHomeError):
            await adguard.disable_protection()


@pytest.mark.asyncio
async def test_verion(event_loop, aresponses):
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
    async with aiohttp.ClientSession(loop=event_loop) as session:
        adguard = AdGuardHome("example.com", session=session, loop=event_loop)
        version = await adguard.version()
        assert version == "1.1"
