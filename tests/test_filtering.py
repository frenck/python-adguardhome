"""Tests for `adguardhome.filtering`."""

import aiohttp
import pytest
from aresponses import Response, ResponsesMockServer

from adguardhome import AdGuardHome
from adguardhome.exceptions import AdGuardHomeError


async def test_enabled(aresponses: ResponsesMockServer) -> None:
    """Test request of current AdGuard Home filter status."""
    aresponses.add(
        "example.com:3000",
        "/control/filtering/status",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"enabled": true}',
        ),
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/status",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"enabled": false}',
        ),
    )
    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        enabled = await adguard.filtering.enabled()
        assert enabled
        enabled = await adguard.filtering.enabled()
        assert not enabled


async def test_enable(aresponses: ResponsesMockServer) -> None:
    """Test enabling AdGuard Home filtering."""

    async def response_handler(request: aiohttp.ClientResponse) -> Response:
        """Response handler for this test."""
        data = await request.json()
        assert data == {"enabled": True, "interval": 1}
        return aresponses.Response(status=200)

    aresponses.add(
        "example.com:3000",
        "/control/filtering/status",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"interval": 1}',
        ),
    )
    aresponses.add(
        "example.com:3000", "/control/filtering/config", "POST", response_handler
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/status",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"interval": 1}',
        ),
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/config",
        "POST",
        aresponses.Response(status=500),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        await adguard.filtering.enable()
        with pytest.raises(AdGuardHomeError):
            await adguard.filtering.enable()


async def test_disable(aresponses: ResponsesMockServer) -> None:
    """Test disabling AdGuard Home filtering."""

    async def response_handler(request: aiohttp.ClientResponse) -> Response:
        """Response handler for this test."""
        data = await request.json()
        assert data == {"enabled": False, "interval": 1}
        return aresponses.Response(status=200)

    aresponses.add(
        "example.com:3000",
        "/control/filtering/status",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"interval": 1}',
        ),
    )
    aresponses.add(
        "example.com:3000", "/control/filtering/config", "POST", response_handler
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/status",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"interval": 1}',
        ),
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/config",
        "POST",
        aresponses.Response(status=400),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        await adguard.filtering.disable()
        with pytest.raises(AdGuardHomeError):
            await adguard.filtering.disable()


async def test_interval(aresponses: ResponsesMockServer) -> None:
    """Test interval settings of the AdGuard Home filtering."""

    async def response_handler(request: aiohttp.ClientResponse) -> Response:
        """Response handler for this test."""
        data = await request.json()
        assert data == {"enabled": True, "interval": 1}
        return aresponses.Response(status=200)

    aresponses.add(
        "example.com:3000",
        "/control/filtering/status",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"interval": 7}',
        ),
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/status",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"enabled": true}',
        ),
    )
    aresponses.add(
        "example.com:3000", "/control/filtering/config", "POST", response_handler
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/status",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"enabled": true}',
        ),
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/config",
        "POST",
        aresponses.Response(status=400),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        interval = await adguard.filtering.interval()
        assert interval == 7
        interval = await adguard.filtering.interval(interval=1)
        assert interval == 1
        with pytest.raises(AdGuardHomeError):
            await adguard.filtering.interval(interval=1)


async def test_rules_count(aresponses: ResponsesMockServer) -> None:
    """Test getting rules count of the AdGuard Home filtering."""
    aresponses.add(
        "example.com:3000",
        "/control/filtering/status",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"filters": [{"rules_count": 99}, {"rules_count": 1}]}',
        ),
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/status",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"filters": []}',
        ),
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/status",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"whitelist_filters": [{"rules_count": 98}, {"rules_count": 1}]}',
        ),
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/status",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"whitelist_filters": null}',
        ),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        result = await adguard.filtering.rules_count(allowlist=False)
        assert result == 100
        result = await adguard.filtering.rules_count(allowlist=False)
        assert result == 0
        result = await adguard.filtering.rules_count(allowlist=True)
        assert result == 99
        result = await adguard.filtering.rules_count(allowlist=True)
        assert result == 0


async def test_add_url(aresponses: ResponsesMockServer) -> None:
    """Test add new filter subscription to AdGuard Home filtering."""

    # Handle to run asserts on request in
    async def response_handler(request: aiohttp.ClientResponse) -> Response:
        """Response handler for this test."""
        data = await request.json()
        assert data == {
            "name": "Example",
            "url": "https://example.com/1.txt",
            "whitelist": False,
        }
        return aresponses.Response(status=200, text="OK 12345 filters added")

    aresponses.add(
        "example.com:3000", "/control/filtering/add_url", "POST", response_handler
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/add_url",
        "POST",
        aresponses.Response(status=400, text="Invalid URL"),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        await adguard.filtering.add_url(
            name="Example", url="https://example.com/1.txt", allowlist=False
        )
        with pytest.raises(AdGuardHomeError):
            await adguard.filtering.add_url(
                name="Example", url="https://example.com/1.txt", allowlist=False
            )


async def test_remove_url(aresponses: ResponsesMockServer) -> None:
    """Test remove filter subscription from AdGuard Home filtering."""

    # Handle to run asserts on request in
    async def response_handler(request: aiohttp.ClientResponse) -> Response:
        """Response handler for this test."""
        data = await request.json()
        assert data == {"url": "https://example.com/1.txt", "whitelist": False}
        return aresponses.Response(status=200, text="OK")

    aresponses.add(
        "example.com:3000", "/control/filtering/remove_url", "POST", response_handler
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/remove_url",
        "POST",
        aresponses.Response(status=400, text="Invalid URL"),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        await adguard.filtering.remove_url(
            allowlist=False, url="https://example.com/1.txt"
        )
        with pytest.raises(AdGuardHomeError):
            await adguard.filtering.remove_url(
                allowlist=False, url="https://example.com/1.txt"
            )


async def test_enable_url(aresponses: ResponsesMockServer) -> None:
    """Test enabling filter subscription in AdGuard Home filtering."""

    # Handle to run asserts on request in
    async def response_handler(request: aiohttp.ClientResponse) -> Response:
        """Response handler for this test."""
        data = await request.json()
        assert data == {
            "url": "https://example.com/1.txt",
            "whitelist": False,
            "data": {
                "enabled": True,
                "url": "https://example.com/1.txt",
                "name": "test",
            },
        }
        return aresponses.Response(status=200, text="OK")

    aresponses.add(
        "example.com:3000",
        "/control/filtering/status",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"filters": [{"url": "https://EXAMPLE.com/1.txt", "name": "test"}]}',
        ),
    )
    aresponses.add(
        "example.com:3000", "/control/filtering/set_url", "POST", response_handler
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/status",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"filters": [{"url": "https://EXAMPLE.com/1.txt", "name": "test"}]}',
        ),
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/set_url",
        "POST",
        aresponses.Response(status=400),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        await adguard.filtering.enable_url(
            allowlist=False, url="https://example.com/1.txt"
        )
        with pytest.raises(AdGuardHomeError):
            await adguard.filtering.enable_url(
                allowlist=False, url="https://example.com/1.txt"
            )


async def test_disable_url(aresponses: ResponsesMockServer) -> None:
    """Test enabling filter subscription in AdGuard Home filtering."""

    # Handle to run asserts on request in
    async def response_handler(request: aiohttp.ClientResponse) -> Response:
        """Response handler for this test."""
        data = await request.json()
        assert data == {
            "url": "https://example.com/1.txt",
            "whitelist": False,
            "data": {
                "enabled": False,
                "name": "test",
                "url": "https://example.com/1.txt",
            },
        }
        return aresponses.Response(status=200)

    aresponses.add(
        "example.com:3000",
        "/control/filtering/status",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"filters": [{"url": "https://EXAMPLE.com/1.txt", "name": "test"}]}',
        ),
    )
    aresponses.add(
        "example.com:3000", "/control/filtering/set_url", "POST", response_handler
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/status",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"filters": [{"url": "https://example.com/1.txt", "name": "test"}]}',
        ),
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/set_url",
        "POST",
        aresponses.Response(status=400),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        await adguard.filtering.disable_url(
            allowlist=False, url="https://example.com/1.txt"
        )
        with pytest.raises(AdGuardHomeError):
            await adguard.filtering.disable_url(
                allowlist=False, url="https://example.com/1.txt"
            )


async def test_refresh(aresponses: ResponsesMockServer) -> None:
    """Test enabling filter subscription in AdGuard Home filtering."""

    async def response_handler_whitelist(request: aiohttp.ClientResponse) -> Response:
        """Response handler for this test."""
        data = await request.json()
        assert data == {"whitelist": True}
        return aresponses.Response(status=200)

    async def response_handler_blocklist(request: aiohttp.ClientResponse) -> Response:
        """Response handler for this test."""
        data = await request.json()
        assert data == {"whitelist": False}
        return aresponses.Response(status=200)

    aresponses.add(
        "example.com:3000",
        "/control/filtering/refresh?force=false",
        "POST",
        response_handler_blocklist,
        match_querystring=True,
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/refresh?force=false",
        "POST",
        response_handler_whitelist,
        match_querystring=True,
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/refresh?force=true",
        "POST",
        aresponses.Response(status=200, text="OK"),
        match_querystring=True,
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/refresh?force=false",
        "POST",
        aresponses.Response(status=400, text="Not OK"),
        match_querystring=True,
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        await adguard.filtering.refresh(allowlist=False, force=False)
        await adguard.filtering.refresh(allowlist=True, force=False)
        await adguard.filtering.refresh(allowlist=False, force=True)
        with pytest.raises(AdGuardHomeError):
            await adguard.filtering.refresh(allowlist=False, force=False)
