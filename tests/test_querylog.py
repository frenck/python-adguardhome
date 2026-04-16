"""Tests for `adguardhome.querylog`."""

import pytest
from aioresponses import CallbackResult, aioresponses

from adguardhome import AdGuardHome
from adguardhome.exceptions import AdGuardHomeError

URL_INFO = "http://example.com:3000/control/querylog_info"
URL_CONFIG = "http://example.com:3000/control/querylog_config"


@pytest.mark.parametrize("enabled", [True, False])
async def test_enabled(
    responses: aioresponses,
    adguard: AdGuardHome,
    enabled: bool,
) -> None:
    """Test reporting the query log enabled status."""
    responses.get(URL_INFO, status=200, payload={"enabled": enabled, "interval": 1})
    assert await adguard.querylog.enabled() is enabled


async def test_enable(responses: aioresponses, adguard: AdGuardHome) -> None:
    """Test enabling the query log."""

    def callback(_url: str, **kwargs: object) -> CallbackResult:
        assert kwargs["json"] == {"enabled": True, "interval": 1}
        return CallbackResult(status=200, content_type="text/plain")

    responses.get(URL_INFO, status=200, payload={"interval": 1})
    responses.post(URL_CONFIG, callback=callback)

    await adguard.querylog.enable()


@pytest.mark.parametrize("status", [400, 500])
async def test_enable_error(
    responses: aioresponses,
    adguard: AdGuardHome,
    status: int,
) -> None:
    """Test enabling the query log fails on HTTP error."""
    responses.get(URL_INFO, status=200, payload={"interval": 1})
    responses.post(URL_CONFIG, status=status, content_type="text/plain")

    with pytest.raises(AdGuardHomeError):
        await adguard.querylog.enable()


async def test_disable(responses: aioresponses, adguard: AdGuardHome) -> None:
    """Test disabling the query log."""

    def callback(_url: str, **kwargs: object) -> CallbackResult:
        assert kwargs["json"] == {"enabled": False, "interval": 1}
        return CallbackResult(status=200, content_type="text/plain")

    responses.get(URL_INFO, status=200, payload={"interval": 1})
    responses.post(URL_CONFIG, callback=callback)

    await adguard.querylog.disable()


@pytest.mark.parametrize("status", [400, 500])
async def test_disable_error(
    responses: aioresponses,
    adguard: AdGuardHome,
    status: int,
) -> None:
    """Test disabling the query log fails on HTTP error."""
    responses.get(URL_INFO, status=200, payload={"interval": 1})
    responses.post(URL_CONFIG, status=status, content_type="text/plain")

    with pytest.raises(AdGuardHomeError):
        await adguard.querylog.disable()


async def test_interval_get(responses: aioresponses, adguard: AdGuardHome) -> None:
    """Test reading the current query log retention interval."""
    responses.get(URL_INFO, status=200, payload={"interval": 7})
    assert await adguard.querylog.interval() == 7


async def test_interval_set(responses: aioresponses, adguard: AdGuardHome) -> None:
    """Test setting the query log retention interval."""

    def callback(_url: str, **kwargs: object) -> CallbackResult:
        assert kwargs["json"] == {"enabled": True, "interval": 1}
        return CallbackResult(status=200, content_type="text/plain")

    responses.get(URL_INFO, status=200, payload={"enabled": True})
    responses.post(URL_CONFIG, callback=callback)

    assert await adguard.querylog.interval(interval=1) == 1


@pytest.mark.parametrize("status", [400, 500])
async def test_interval_set_error(
    responses: aioresponses,
    adguard: AdGuardHome,
    status: int,
) -> None:
    """Test setting the query log interval fails on HTTP error."""
    responses.get(URL_INFO, status=200, payload={"enabled": True})
    responses.post(URL_CONFIG, status=status, content_type="text/plain")

    with pytest.raises(AdGuardHomeError):
        await adguard.querylog.interval(interval=1)
