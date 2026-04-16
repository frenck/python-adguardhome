"""Tests for `adguardhome.safesearch`."""

import pytest
from aioresponses import aioresponses

from adguardhome import AdGuardHome
from adguardhome.exceptions import AdGuardHomeError

URL_STATUS = "http://example.com:3000/control/safesearch/status"
URL_ENABLE = "http://example.com:3000/control/safesearch/enable"
URL_DISABLE = "http://example.com:3000/control/safesearch/disable"


@pytest.mark.parametrize("enabled", [True, False])
async def test_enabled(
    responses: aioresponses,
    adguard: AdGuardHome,
    enabled: bool,
) -> None:
    """Test reporting safe search enforcing status."""
    responses.get(URL_STATUS, status=200, payload={"enabled": enabled})
    assert await adguard.safesearch.enabled() is enabled


async def test_enable(responses: aioresponses, adguard: AdGuardHome) -> None:
    """Test enabling safe search enforcing."""
    responses.post(URL_ENABLE, status=200, body="OK", content_type="text/plain")
    await adguard.safesearch.enable()


@pytest.mark.parametrize("status", [400, 500])
async def test_enable_error(
    responses: aioresponses,
    adguard: AdGuardHome,
    status: int,
) -> None:
    """Test enabling safe search enforcing fails on HTTP error."""
    responses.post(URL_ENABLE, status=status, body="NOT OK", content_type="text/plain")
    with pytest.raises(AdGuardHomeError):
        await adguard.safesearch.enable()


async def test_disable(responses: aioresponses, adguard: AdGuardHome) -> None:
    """Test disabling safe search enforcing."""
    responses.post(URL_DISABLE, status=200, body="OK", content_type="text/plain")
    await adguard.safesearch.disable()


@pytest.mark.parametrize("status", [400, 500])
async def test_disable_error(
    responses: aioresponses,
    adguard: AdGuardHome,
    status: int,
) -> None:
    """Test disabling safe search enforcing fails on HTTP error."""
    responses.post(URL_DISABLE, status=status, body="NOT OK", content_type="text/plain")
    with pytest.raises(AdGuardHomeError):
        await adguard.safesearch.disable()
