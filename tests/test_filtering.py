"""Tests for `adguardhome.filtering`."""
import aiohttp
import pytest
from adguardhome import AdGuardHome, types
from adguardhome.exceptions import AdGuardHomeError


@pytest.mark.asyncio
async def test_enabled(aresponses):
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


@pytest.mark.asyncio
async def test_enable(aresponses):
    """Test enabling AdGuard Home filtering."""

    async def response_handler(request):
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


@pytest.mark.asyncio
async def test_disable(aresponses):
    """Test disabling AdGuard Home filtering."""

    async def response_handler(request):
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


@pytest.mark.asyncio
async def test_interval(aresponses):
    """Test interval settings of the AdGuard Home filtering."""

    async def response_handler(request):
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


@pytest.mark.asyncio
async def test_rules_count(aresponses):
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

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        result = await adguard.filtering.rules_count()
        assert result == 100
        result = await adguard.filtering.rules_count()
        assert result == 0


@pytest.mark.asyncio
async def test_add_url(aresponses):
    """Test add new filter subscription to AdGuard Home filtering."""
    # Handle to run asserts on request in
    async def response_handler(request):
        data = await request.json()
        assert data == {"name": "Example", "url": "https://example.com/1.txt"}
        return aresponses.Response(status=200, text="OK 12345 filters added")

    aresponses.add(
        "example.com:3000", "/control/filtering/add_url", "POST", response_handler
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/add_url",
        "POST",
        aresponses.Response(status=200, text="Invalid URL"),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        await adguard.filtering.add_url("Example", "https://example.com/1.txt")
        with pytest.raises(AdGuardHomeError):
            await adguard.filtering.add_url("Example", "https://example.com/1.txt")


@pytest.mark.asyncio
async def test_remove_url(aresponses):
    """Test remove filter subscription from AdGuard Home filtering."""
    # Handle to run asserts on request in
    async def response_handler(request):
        data = await request.json()
        assert data == {"url": "https://example.com/1.txt"}
        return aresponses.Response(status=200, text="OK")

    aresponses.add(
        "example.com:3000", "/control/filtering/remove_url", "POST", response_handler
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/remove_url",
        "POST",
        aresponses.Response(status=200, text="Invalid URL"),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        await adguard.filtering.remove_url("https://example.com/1.txt")
        with pytest.raises(AdGuardHomeError):
            await adguard.filtering.remove_url("https://example.com/1.txt")


@pytest.mark.asyncio
async def test_enable_url(aresponses):
    """Test enabling filter subscription in AdGuard Home filtering."""
    # Handle to run asserts on request in
    async def response_handler(request):
        data = await request.json()
        assert data == {"url": "https://example.com/1.txt", "enabled": True}
        return aresponses.Response(status=200, text="OK")

    aresponses.add(
        "example.com:3000", "/control/filtering/set_url", "POST", response_handler
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/set_url",
        "POST",
        aresponses.Response(status=400),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        await adguard.filtering.enable_url("https://example.com/1.txt")
        with pytest.raises(AdGuardHomeError):
            await adguard.filtering.enable_url("https://example.com/1.txt")


@pytest.mark.asyncio
async def test_disable_url(aresponses):
    """Test enabling filter subscription in AdGuard Home filtering."""
    # Handle to run asserts on request in
    async def response_handler(request):
        data = await request.json()
        assert data == {"url": "https://example.com/1.txt", "enabled": False}
        return aresponses.Response(status=200)

    aresponses.add(
        "example.com:3000", "/control/filtering/set_url", "POST", response_handler
    )
    aresponses.add(
        "example.com:3000",
        "/control/filtering/set_url",
        "POST",
        aresponses.Response(status=400),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        await adguard.filtering.disable_url("https://example.com/1.txt")
        with pytest.raises(AdGuardHomeError):
            await adguard.filtering.disable_url("https://example.com/1.txt")


@pytest.mark.asyncio
async def test_refresh(aresponses):
    """Test enabling filter subscription in AdGuard Home filtering."""
    aresponses.add(
        "example.com:3000",
        "/control/filtering/refresh?force=false",
        "POST",
        aresponses.Response(status=200, text="OK"),
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
        aresponses.Response(status=200, text="Not OK"),
        match_querystring=True,
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        await adguard.filtering.refresh(False)
        await adguard.filtering.refresh(True)
        with pytest.raises(AdGuardHomeError):
            await adguard.filtering.refresh(False)


@pytest.mark.asyncio
async def test_status(aresponses):
    """Test getting rules count of the AdGuard Home filtering."""
    aresponses.add(
        "example.com:3000",
        "/control/filtering/status",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"enabled":true,"interval":1,"filters":[{"id":1591149173,"enabled":true,"url":"https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt","name":"AdGuard Simplified Domain Names filter","rules_count":37359,"last_updated":"2020-06-06T09:49:51Z"}],"whitelist_filters":null,"user_rules":[]}',
        ),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        result = await adguard.filtering.status()
        assert isinstance(result, types.Status)


@pytest.mark.asyncio
async def test_check_host(aresponses):
    """Test getting rules count of the AdGuard Home filtering."""
    aresponses.add(
        "example.com:3000",
        "/control/filtering/check_host",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text='{"reason":"NotFilteredNotFound","filter_id":0,"rule":"","service_name":"","cname":"","ip_addrs":null}',
        ),
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        result = await adguard.filtering.check_host(name="example.com")
        assert isinstance(result, types.Check_Host)
