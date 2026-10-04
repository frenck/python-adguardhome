"""Tests for `adguardhome.toggle`, used by parental control and safe browsing."""

import pytest
from aiointercept import aiointercept
from yarl import URL

from adguardhome import AdGuardHome, AdGuardHomeError

URL_BASE = "http://example.com:3000/control"

pytestmark = pytest.mark.parametrize("feature", ["parental", "safebrowsing"])


@pytest.mark.parametrize("enabled", [True, False])
async def test_enabled(
    responses: aiointercept, adguard: AdGuardHome, feature: str, enabled: bool
) -> None:
    """Test reading if the feature is enabled."""
    responses.get(
        f"{URL_BASE}/{feature}/status", status=200, payload={"enabled": enabled}
    )

    assert await getattr(adguard, feature).enabled() is enabled


async def test_enabled_unexpected_data(
    responses: aiointercept, adguard: AdGuardHome, feature: str
) -> None:
    """Test a status without the enabled state raises an error."""
    responses.get(f"{URL_BASE}/{feature}/status", status=200, payload={})

    with pytest.raises(AdGuardHomeError, match="Unexpected ToggleStatus data"):
        await getattr(adguard, feature).enabled()


@pytest.mark.parametrize("method", ["enable", "disable"])
async def test_enable_disable(
    responses: aiointercept, adguard: AdGuardHome, feature: str, method: str
) -> None:
    """Test turning the feature on and off."""
    url = f"{URL_BASE}/{feature}/{method}"
    responses.post(url, status=200, body="OK\n", content_type="text/plain")

    await getattr(getattr(adguard, feature), method)()

    assert responses.requests is not None
    assert ("POST", URL(url)) in responses.requests
