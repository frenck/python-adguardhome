"""Tests for `adguardhome.stats`."""

from datetime import timedelta
from typing import Any

import pytest
from aiointercept import CallbackResult, aiointercept
from syrupy.assertion import SnapshotAssertion
from yarl import URL

from adguardhome import (
    AdGuardHome,
    AdGuardHomeError,
    Stats,
    StatsConfig,
    TimeUnit,
)

from .conftest import FixtureLoader

URL_STATS = "http://example.com:3000/control/stats"
URL_STATS_CONFIG = "http://example.com:3000/control/stats/config"
URL_STATS_CONFIG_UPDATE = "http://example.com:3000/control/stats/config/update"
URL_STATS_RESET = "http://example.com:3000/control/stats_reset"


async def test_stats(
    responses: aiointercept,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
    snapshot: SnapshotAssertion,
) -> None:
    """Test the statistics are parsed into a model with a single request."""
    responses.get(URL_STATS, status=200, payload=load_fixture("stats"))

    stats = await adguard.stats.get()

    assert stats == snapshot
    assert stats.dns_queries == 1440
    assert stats.blocked_filtering == 265
    assert stats.blocked_safebrowsing == 2
    assert stats.avg_processing_time == timedelta(microseconds=18744)
    assert stats.time_unit is TimeUnit.HOURS
    assert len(stats.dns_queries_history) == 24


async def test_stats_top_lists_keep_order(
    responses: aiointercept,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
) -> None:
    """Test the top lists become dictionaries ordered from the top down."""
    responses.get(URL_STATS, status=200, payload=load_fixture("stats"))

    stats = await adguard.stats.get()

    assert list(stats.top_queried_domains) == [
        "connectivity-check.ubuntu.com",
        "api.github.com",
        "time.cloudflare.com",
    ]
    assert stats.top_clients == {"192.168.1.20": 1021, "192.168.1.33": 419}
    assert stats.top_upstream_avg_time == {
        "tls://1.1.1.1": timedelta(milliseconds=12.5),
        "https://dns.quad9.net:443/dns-query": timedelta(milliseconds=31),
    }


def test_stats_serializes_to_api_format(load_fixture: FixtureLoader) -> None:
    """Test statistics serialize back to the format of the AdGuard Home API."""
    data = load_fixture("stats")

    assert Stats.from_api(data).to_dict() == data


def test_stats_without_top_lists_and_history() -> None:
    """Test statistics without top lists and history default to empty."""
    stats = Stats.from_api(
        {
            "time_units": "days",
            "num_dns_queries": 0,
            "num_blocked_filtering": 0,
            "num_replaced_safebrowsing": 0,
            "num_replaced_safesearch": 0,
            "num_replaced_parental": 0,
            "avg_processing_time": 0,
        }
    )

    assert stats.time_unit is TimeUnit.DAYS
    assert stats.top_queried_domains == {}
    assert stats.dns_queries_history == ()


@pytest.mark.parametrize(
    ("dns_queries", "blocked_filtering", "expected"),
    [
        (1440, 265, 18.40277),
        (100, 100, 100.0),
        (0, 0, 0.0),
    ],
)
def test_blocked_percentage(
    load_fixture: FixtureLoader,
    dns_queries: int,
    blocked_filtering: int,
    expected: float,
) -> None:
    """Test the blocked percentage, also without any queries at all."""
    stats = Stats.from_api(
        load_fixture("stats")
        | {"num_dns_queries": dns_queries, "num_blocked_filtering": blocked_filtering}
    )

    assert stats.blocked_percentage == pytest.approx(expected, abs=1e-5)


async def test_stats_unexpected_data(
    responses: aiointercept, adguard: AdGuardHome
) -> None:
    """Test statistics that do not fit the model raise an error."""
    responses.get(URL_STATS, status=200, payload={"time_units": "weeks"})

    with pytest.raises(AdGuardHomeError, match="Unexpected Stats data"):
        await adguard.stats.get()


async def test_config(
    responses: aiointercept,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
) -> None:
    """Test the statistics configuration is parsed into a model."""
    responses.get(URL_STATS_CONFIG, status=200, payload=load_fixture("stats_config"))

    config = await adguard.stats.config()

    assert config == StatsConfig(
        enabled=True,
        retention=timedelta(days=1),
        ignored=("example.com", "*.lan"),
        ignored_enabled=True,
    )


async def test_config_before_ignored_enabled(
    responses: aiointercept,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
) -> None:
    """Test a configuration from before `ignored_enabled` round-trips as is."""
    data = load_fixture("stats_config_legacy")
    responses.get(URL_STATS_CONFIG, status=200, payload=data)

    config = await adguard.stats.config()

    assert config.ignored_enabled is None
    assert config.retention == timedelta(days=90)
    assert config.to_dict() == data


async def test_set_config(responses: aiointercept, adguard: AdGuardHome) -> None:
    """Test the configuration is sent in the format of the API."""

    def callback(_url: str, **kwargs: Any) -> CallbackResult:
        assert kwargs["json"] == {
            "enabled": True,
            "interval": 604_800_000,
            "ignored": ["example.com"],
        }
        return CallbackResult(status=200, body="OK\n", content_type="text/plain")

    responses.put(URL_STATS_CONFIG_UPDATE, callback=callback)

    await adguard.stats.set_config(
        StatsConfig(
            enabled=True,
            retention=timedelta(days=7),
            ignored=("example.com",),
        )
    )


@pytest.mark.parametrize(
    ("method", "enabled"),
    [
        ("enable", True),
        ("disable", False),
    ],
)
async def test_enable_disable(
    responses: aiointercept,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
    method: str,
    enabled: bool,
) -> None:
    """Test toggling statistics only changes `enabled` in the configuration."""
    data = load_fixture("stats_config")
    responses.get(URL_STATS_CONFIG, status=200, payload=data)

    def callback(_url: str, **kwargs: Any) -> CallbackResult:
        assert kwargs["json"] == data | {"enabled": enabled}
        return CallbackResult(status=200, body="OK\n", content_type="text/plain")

    responses.put(URL_STATS_CONFIG_UPDATE, callback=callback)

    await getattr(adguard.stats, method)()


async def test_reset(responses: aiointercept, adguard: AdGuardHome) -> None:
    """Test resetting the statistics."""
    responses.post(URL_STATS_RESET, status=200, body="OK\n", content_type="text/plain")

    await adguard.stats.reset()

    assert responses.requests is not None
    assert ("POST", URL(URL_STATS_RESET)) in responses.requests
