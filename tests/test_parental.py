"""Tests for `adguardhome.parental`."""

import pytest
from aioresponses import aioresponses

from adguardhome import AdGuardHome
from adguardhome.exceptions import AdGuardHomeError

URL_STATUS = "http://example.com:3000/control/parental/status"
URL_ENABLE = "http://example.com:3000/control/parental/enable"
URL_DISABLE = "http://example.com:3000/control/parental/disable"


@pytest.mark.parametrize("enabled", [True, False])
async def test_enabled(
    responses: aioresponses,
    adguard: AdGuardHome,
    enabled: bool,
) -> None:
    """Test reporting parental control status."""
    responses.get(URL_STATUS, status=200, payload={"enabled": enabled})
    assert await adguard.parental.enabled() is enabled


async def test_enable(responses: aioresponses, adguard: AdGuardHome) -> None:
    """Test enabling parental control."""
    responses.post(URL_ENABLE, status=200, body="OK", content_type="text/plain")
    await adguard.parental.enable()


@pytest.mark.parametrize("status", [400, 500])
async def test_enable_error(
    responses: aioresponses,
    adguard: AdGuardHome,
    status: int,
) -> None:
    """Test enabling parental control fails on HTTP error."""
    responses.post(URL_ENABLE, status=status, body="NOT OK", content_type="text/plain")
    with pytest.raises(AdGuardHomeError):
        await adguard.parental.enable()


async def test_disable(responses: aioresponses, adguard: AdGuardHome) -> None:
    """Test disabling parental control."""
    responses.post(URL_DISABLE, status=200, body="OK", content_type="text/plain")
    await adguard.parental.disable()


@pytest.mark.parametrize("status", [400, 500])
async def test_disable_error(
    responses: aioresponses,
    adguard: AdGuardHome,
    status: int,
) -> None:
    """Test disabling parental control fails on HTTP error."""
    responses.post(URL_DISABLE, status=status, body="NOT OK", content_type="text/plain")
    with pytest.raises(AdGuardHomeError):
        await adguard.parental.disable()
