"""Tests for `adguardhome.dns`."""

from dataclasses import replace
from datetime import timedelta
from typing import Any

import pytest
from aiointercept import CallbackResult, aiointercept
from syrupy.assertion import SnapshotAssertion
from yarl import URL

from adguardhome import (
    AdGuardHome,
    AdGuardHomeError,
    BlockingMode,
    DnsConfig,
    UpstreamMode,
)

from .conftest import FixtureLoader

URL_BASE = "http://example.com:3000/control"
URL_DNS_INFO = f"{URL_BASE}/dns_info"
URL_DNS_CONFIG = f"{URL_BASE}/dns_config"
URL_CACHE_CLEAR = f"{URL_BASE}/cache_clear"
URL_TEST_UPSTREAMS = f"{URL_BASE}/test_upstream_dns"


async def test_config(
    responses: aiointercept,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
    snapshot: SnapshotAssertion,
) -> None:
    """Test the DNS settings are parsed into a model."""
    responses.get(URL_DNS_INFO, status=200, payload=load_fixture("dns_info"))

    config = await adguard.dns.config()

    assert config == snapshot
    assert config.upstream_dns[0] == "https://dns.quad9.net/dns-query"
    assert config.upstream_timeout == timedelta(seconds=10)
    assert config.cache_ttl_max == timedelta(days=1)
    assert config.blocking_mode is BlockingMode.DEFAULT
    assert config.ratelimit_allowlist == ("192.168.1.2",)
    assert config.fallback_dns == ()


async def test_config_not_set(
    responses: aiointercept,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
) -> None:
    """Test values AdGuard Home sends as empty strings are None."""
    responses.get(URL_DNS_INFO, status=200, payload=load_fixture("dns_info"))

    config = await adguard.dns.config()

    assert config.upstream_dns_file is None
    assert config.blocking_ipv4 is None
    assert config.blocking_ipv6 is None
    assert config.edns_cs_custom_ip is None


async def test_config_load_balance(
    responses: aiointercept,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
) -> None:
    """Test an empty upstream mode, how AdGuard Home reports load balancing."""
    responses.get(URL_DNS_INFO, status=200, payload=load_fixture("dns_info"))

    config = await adguard.dns.config()

    assert config.upstream_mode is UpstreamMode.LOAD_BALANCE
    assert config.to_dict()["upstream_mode"] == "load_balance"


async def test_set_config(
    responses: aiointercept,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
) -> None:
    """Test the settings are sent without protection or read-only fields."""
    data = load_fixture("dns_info")
    responses.get(URL_DNS_INFO, status=200, payload=data)
    config = await adguard.dns.config()

    def callback(_url: URL, **kwargs: Any) -> CallbackResult:
        sent = kwargs["json"]
        assert "protection_enabled" not in sent
        assert "protection_disabled_until" not in sent
        assert "default_local_ptr_upstreams" not in sent
        assert "blocking_ipv4" not in sent
        assert sent["blocking_mode"] == "custom_ip"
        assert sent["blocking_ipv6"] == "::1"
        assert sent["upstream_timeout"] == 30
        assert sent["ratelimit_whitelist"] == ["192.168.1.2"]
        return CallbackResult(status=200, body="OK\n", content_type="text/plain")

    responses.post(URL_DNS_CONFIG, callback=callback)

    await adguard.dns.set_config(
        replace(
            config,
            blocking_mode=BlockingMode.CUSTOM_IP,
            blocking_ipv6="::1",
            upstream_timeout=timedelta(seconds=30),
        )
    )


@pytest.mark.parametrize(
    ("field", "name"),
    [
        ("upstream_timeout", "upstream timeout"),
        ("blocked_response_ttl", "blocked response TTL"),
        ("cache_ttl_min", "minimum cache TTL"),
        ("cache_ttl_max", "maximum cache TTL"),
    ],
)
def test_config_rejects_partial_seconds(
    load_fixture: FixtureLoader, field: str, name: str
) -> None:
    """Test a duration with a partial second is rejected, not rounded."""
    config = DnsConfig.from_api(load_fixture("dns_info"))

    with pytest.raises(ValueError, match=f"{name} must be a whole number of seconds"):
        replace(config, **{field: timedelta(seconds=1.5)})


async def test_clear_cache(responses: aiointercept, adguard: AdGuardHome) -> None:
    """Test clearing the DNS cache."""
    responses.post(URL_CACHE_CLEAR, status=200, body="OK", content_type="text/plain")

    await adguard.dns.clear_cache()

    assert responses.requests is not None
    assert ("POST", URL(URL_CACHE_CLEAR)) in responses.requests


async def test_test_upstreams(responses: aiointercept, adguard: AdGuardHome) -> None:
    """Test testing upstreams returns None for a working one, else the error."""

    def callback(_url: URL, **kwargs: Any) -> CallbackResult:
        assert kwargs["json"] == {
            "upstream_dns": ["tls://1.1.1.1", "tls://dns.invalid"],
            "bootstrap_dns": ["9.9.9.10"],
            "fallback_dns": [],
            "private_upstream": ["192.168.1.1"],
        }
        return CallbackResult(
            status=200,
            payload={
                "tls://1.1.1.1": "OK",
                "tls://dns.invalid": "couldn't communicate with upstream",
                "192.168.1.1": "OK",
            },
        )

    responses.post(URL_TEST_UPSTREAMS, callback=callback)

    results = await adguard.dns.test_upstreams(
        ["tls://1.1.1.1", "tls://dns.invalid"],
        bootstrap_dns=["9.9.9.10"],
        local_ptr_upstreams=["192.168.1.1"],
    )

    assert results == {
        "tls://1.1.1.1": None,
        "tls://dns.invalid": "couldn't communicate with upstream",
        "192.168.1.1": None,
    }


async def test_test_upstreams_unexpected_response(
    responses: aiointercept, adguard: AdGuardHome
) -> None:
    """Test an upstream test response that is not an object raises an error."""
    responses.post(URL_TEST_UPSTREAMS, status=200, payload=["OK"])

    with pytest.raises(AdGuardHomeError, match="Unexpected upstream test response"):
        await adguard.dns.test_upstreams(["tls://1.1.1.1"])
