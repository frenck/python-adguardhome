"""Tests for `adguardhome.querylog`."""

from datetime import timedelta
from typing import Any

import pytest
from aiointercept import CallbackResult, aiointercept
from yarl import URL

from adguardhome import AdGuardHome, QueryLogConfig

URL_CONFIG = "http://example.com:3000/control/querylog/config"
URL_CONFIG_UPDATE = "http://example.com:3000/control/querylog/config/update"
URL_CLEAR = "http://example.com:3000/control/querylog_clear"

CONFIG: dict[str, Any] = {
    "enabled": True,
    "interval": 2_592_000_000,
    "anonymize_client_ip": False,
    "ignored": ["*.lan"],
    "ignored_enabled": True,
}


async def test_config(responses: aiointercept, adguard: AdGuardHome) -> None:
    """Test the query log configuration is parsed into a model."""
    responses.get(URL_CONFIG, status=200, payload=CONFIG)

    config = await adguard.querylog.config()

    assert config == QueryLogConfig(
        enabled=True,
        retention=timedelta(days=30),
        anonymize_client_ip=False,
        ignored=("*.lan",),
        ignored_enabled=True,
    )
    assert config.to_dict() == CONFIG


async def test_config_before_ignored_enabled(
    responses: aiointercept, adguard: AdGuardHome
) -> None:
    """Test a configuration from before `ignored_enabled` round-trips as is."""
    data: dict[str, Any] = {
        key: value for key, value in CONFIG.items() if key != "ignored_enabled"
    }
    data["ignored"] = None
    responses.get(URL_CONFIG, status=200, payload=data)

    config = await adguard.querylog.config()

    assert config.ignored == ()
    assert config.ignored_enabled is None
    assert "ignored_enabled" not in config.to_dict()


@pytest.mark.parametrize(("method", "enabled"), [("enable", True), ("disable", False)])
async def test_enable_disable(
    responses: aiointercept, adguard: AdGuardHome, method: str, enabled: bool
) -> None:
    """Test toggling the query log only changes `enabled`."""
    responses.get(URL_CONFIG, status=200, payload=CONFIG)

    def callback(_url: URL, **kwargs: Any) -> CallbackResult:
        assert kwargs["json"] == CONFIG | {"enabled": enabled}
        return CallbackResult(status=200, body="OK\n", content_type="text/plain")

    responses.put(URL_CONFIG_UPDATE, callback=callback)

    await getattr(adguard.querylog, method)()


async def test_clear(responses: aiointercept, adguard: AdGuardHome) -> None:
    """Test clearing the query log."""
    responses.post(URL_CLEAR, status=200, body="OK\n", content_type="text/plain")

    await adguard.querylog.clear()

    assert responses.requests is not None
    assert ("POST", URL(URL_CLEAR)) in responses.requests
