"""Tests for `adguardhome.safesearch`."""

from typing import Any

import pytest
from aiointercept import CallbackResult, aiointercept
from yarl import URL

from adguardhome import AdGuardHome, SafeSearchConfig

URL_STATUS = "http://example.com:3000/control/safesearch/status"
URL_SETTINGS = "http://example.com:3000/control/safesearch/settings"

CONFIG = {
    "enabled": True,
    "bing": True,
    "duckduckgo": True,
    "ecosia": True,
    "google": True,
    "pixabay": False,
    "yandex": False,
    "youtube": True,
}


async def test_config(responses: aiointercept, adguard: AdGuardHome) -> None:
    """Test the safe search configuration is parsed into a model."""
    responses.get(URL_STATUS, status=200, payload=CONFIG)

    config = await adguard.safesearch.config()

    assert config == SafeSearchConfig(
        enabled=True,
        bing=True,
        duckduckgo=True,
        ecosia=True,
        google=True,
        youtube=True,
    )
    assert config.to_dict() == CONFIG


@pytest.mark.parametrize(("method", "enabled"), [("enable", True), ("disable", False)])
async def test_enable_disable(
    responses: aiointercept, adguard: AdGuardHome, method: str, enabled: bool
) -> None:
    """Test toggling safe search keeps the settings per service."""
    responses.get(URL_STATUS, status=200, payload=CONFIG)

    def callback(_url: URL, **kwargs: Any) -> CallbackResult:
        assert kwargs["json"] == CONFIG | {"enabled": enabled}
        return CallbackResult(status=200, body="OK\n", content_type="text/plain")

    responses.put(URL_SETTINGS, callback=callback)

    await getattr(adguard.safesearch, method)()
