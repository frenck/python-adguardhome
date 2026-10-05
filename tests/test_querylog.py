"""Tests for `adguardhome.querylog`."""

import re
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from aiointercept import CallbackResult, aiointercept
from syrupy.assertion import SnapshotAssertion
from yarl import URL

from adguardhome import (
    AdGuardHome,
    AdGuardHomeError,
    DnsAnswer,
    FilteringReason,
    QueryLog,
    QueryLogConfig,
)

from .conftest import FixtureLoader

URL_QUERYLOG = "http://example.com:3000/control/querylog"
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


async def test_get(
    responses: aiointercept,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
    snapshot: SnapshotAssertion,
) -> None:
    """Test a page of the query log is parsed into models."""
    responses.get(URL_QUERYLOG, status=200, payload=load_fixture("querylog"))

    log = await adguard.querylog.get()

    assert log == snapshot
    assert len(log.entries) == 2
    assert log.oldest == datetime(2025, 10, 3, 14, 0, 0, 500000, tzinfo=UTC)


async def test_get_entry_not_filtered(
    responses: aiointercept,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
) -> None:
    """Test a plain DNS query that AdGuard Home answered from upstream."""
    responses.get(URL_QUERYLOG, status=200, payload=load_fixture("querylog"))

    entry = (await adguard.querylog.get()).entries[0]

    assert not entry.filtered
    assert entry.reason is FilteringReason.NOT_FILTERED_NOT_FOUND
    # Go sends nanoseconds, Python keeps microseconds.
    assert entry.time == datetime(2025, 10, 3, 14, 0, 1, 123456, tzinfo=UTC)
    assert entry.elapsed == timedelta(microseconds=12346)
    assert entry.question.name == "example.com"
    assert entry.question.dns_class == "IN"
    assert entry.question.unicode_name is None
    assert entry.answer[0] == DnsAnswer(
        type="A", value="93.184.215.14", ttl=timedelta(hours=1)
    )
    assert entry.client_ip == "192.168.1.20"
    assert entry.client_info is not None
    assert entry.client_info.name == "laptop.lan"
    assert entry.client_proto is None
    assert entry.client_id is None
    assert entry.upstream == "https://dns.quad9.net:443/dns-query"
    assert entry.status == "NOERROR"


async def test_get_entry_filtered(
    responses: aiointercept,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
) -> None:
    """Test a cached DNS over HTTPS query that a blocklist filtered."""
    responses.get(URL_QUERYLOG, status=200, payload=load_fixture("querylog"))

    entry = (await adguard.querylog.get()).entries[1]

    assert entry.filtered
    assert entry.rules[0].text == "||xn--mgbh0fb.xn--kgbechtv^"
    assert entry.question.unicode_name == "مثال.إختبار"
    assert entry.original_answer[0].value == "203.0.113.10"
    assert entry.cached
    assert entry.upstream is None
    assert entry.client_proto == "doh"
    assert entry.client_id == "kids-tablet"
    assert entry.ecs == "192.168.1.0/24"


async def test_get_empty(responses: aiointercept, adguard: AdGuardHome) -> None:
    """Test an empty page, for which AdGuard Home sends an empty `oldest`."""
    responses.get(URL_QUERYLOG, status=200, payload={"data": [], "oldest": ""})

    assert await adguard.querylog.get() == QueryLog()


async def test_get_with_parameters(
    responses: aiointercept, adguard: AdGuardHome
) -> None:
    """Test searching, limiting, and paging send their query parameters."""

    def callback(_url: URL, **kwargs: Any) -> CallbackResult:
        assert kwargs["query"] == {
            "search": ["example.com"],
            "limit": ["50"],
            "older_than": ["2025-10-03T14:00:00.500000+00:00"],
        }
        return CallbackResult(status=200, payload={"data": None, "oldest": ""})

    responses.get(re.compile(rf"^{re.escape(URL_QUERYLOG)}\?"), callback=callback)

    await adguard.querylog.get(
        search="example.com",
        limit=50,
        older_than=datetime(2025, 10, 3, 14, 0, 0, 500000, tzinfo=UTC),
    )


async def test_get_unexpected_reason(
    responses: aiointercept, adguard: AdGuardHome, load_fixture: FixtureLoader
) -> None:
    """Test an entry with a reason we do not know raises an error."""
    page = load_fixture("querylog")
    page["data"][0]["reason"] = "FilteredSomethingNew"
    responses.get(URL_QUERYLOG, status=200, payload=page)

    with pytest.raises(AdGuardHomeError, match="Unexpected QueryLog data"):
        await adguard.querylog.get()


def test_entry_serializes_to_api_format(load_fixture: FixtureLoader) -> None:
    """Test an entry serializes back to the field names of the API."""
    data = load_fixture("querylog")["data"][1]

    serialized = QueryLog.from_api({"data": [data]}).entries[0].to_dict()

    assert serialized["elapsedMs"] == "0.051"
    assert serialized["question"]["class"] == "IN"
    assert serialized["answer"][0]["ttl"] == 10


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
