"""Tests for `adguardhome.filtering`."""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from aiointercept import CallbackResult, aiointercept
from syrupy.assertion import SnapshotAssertion
from yarl import URL

from adguardhome import (
    AdGuardHome,
    AdGuardHomeError,
    FilteringConfig,
    FilteringReason,
    FilteringStatus,
)

from .conftest import FixtureLoader

URL_BASE = "http://example.com:3000/control/filtering"
URL_STATUS = f"{URL_BASE}/status"
URL_CONFIG = f"{URL_BASE}/config"
URL_ADD = f"{URL_BASE}/add_url"
URL_REMOVE = f"{URL_BASE}/remove_url"
URL_SET = f"{URL_BASE}/set_url"
URL_REFRESH = f"{URL_BASE}/refresh"
URL_SET_RULES = f"{URL_BASE}/set_rules"
URL_CHECK_HOST = f"{URL_BASE}/check_host"

URL_DNS_FILTER = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"
URL_EXAMPLE_ADS = "https://example.com/Ads.txt"


def ok(payload: Any = None) -> CallbackResult:
    """Return the response AdGuard Home gives on a successful action."""
    if payload is not None:
        return CallbackResult(status=200, payload=payload)
    return CallbackResult(status=200, body="OK\n", content_type="text/plain")


def expect_json(expected: Any, payload: Any = None) -> Any:
    """Return a callback asserting the JSON body of the request."""

    def callback(_url: URL, **kwargs: Any) -> CallbackResult:
        assert kwargs["json"] == expected
        return ok(payload)

    return callback


@pytest.fixture
def status(responses: aiointercept, load_fixture: FixtureLoader) -> None:
    """Mock the filtering status, which most operations read first."""
    responses.get(
        URL_STATUS, status=200, payload=load_fixture("filtering_status"), repeat=True
    )


@pytest.mark.usefixtures("status")
async def test_get(adguard: AdGuardHome, snapshot: SnapshotAssertion) -> None:
    """Test the filtering status is parsed into a model."""
    filtering = await adguard.filtering.get()

    assert filtering == snapshot
    assert filtering.enabled
    assert filtering.update_interval == timedelta(days=1)
    assert len(filtering.blocklists) == 2
    assert filtering.blocklists[0].last_updated == datetime(
        2025, 10, 3, 12, 0, tzinfo=UTC
    )
    assert filtering.blocklists[1].last_updated is None
    assert filtering.allowlists == ()
    assert len(filtering.user_rules) == 3


def test_status_serializes_to_api_format(load_fixture: FixtureLoader) -> None:
    """Test the status round-trips, with a null list coming back empty."""
    data = load_fixture("filtering_status")
    filtering = FilteringStatus.from_api(data)

    assert FilteringStatus.from_api(filtering.to_dict()) == filtering
    assert filtering.to_dict()["whitelist_filters"] == []


@pytest.mark.usefixtures("status")
async def test_config(adguard: AdGuardHome) -> None:
    """Test the configuration only holds the configuration."""
    assert await adguard.filtering.config() == FilteringConfig(
        enabled=True, update_interval=timedelta(hours=24)
    )


async def test_set_config(responses: aiointercept, adguard: AdGuardHome) -> None:
    """Test the configuration is sent in the format of the API."""
    responses.post(
        URL_CONFIG, callback=expect_json({"enabled": False, "interval": 168})
    )

    await adguard.filtering.set_config(
        FilteringConfig(enabled=False, update_interval=timedelta(weeks=1))
    )


@pytest.mark.usefixtures("status")
async def test_set_config_from_status(
    responses: aiointercept, adguard: AdGuardHome
) -> None:
    """Test passing a full status only sends its configuration."""
    responses.post(URL_CONFIG, callback=expect_json({"enabled": True, "interval": 1}))

    filtering = await adguard.filtering.get()
    await adguard.filtering.set_config(
        FilteringStatus(
            enabled=filtering.enabled,
            update_interval=timedelta(hours=1),
            blocklists=filtering.blocklists,
        )
    )


@pytest.mark.parametrize(("method", "enabled"), [("enable", True), ("disable", False)])
@pytest.mark.usefixtures("status")
async def test_enable_disable(
    responses: aiointercept, adguard: AdGuardHome, method: str, enabled: bool
) -> None:
    """Test toggling filtering keeps the update interval."""
    responses.post(
        URL_CONFIG, callback=expect_json({"enabled": enabled, "interval": 24})
    )

    await getattr(adguard.filtering, method)()


@pytest.mark.parametrize(
    ("kind", "count", "first_url"),
    [("blocklists", 2, URL_DNS_FILTER), ("allowlists", 0, None)],
)
@pytest.mark.usefixtures("status")
async def test_list(
    adguard: AdGuardHome, kind: str, count: int, first_url: str | None
) -> None:
    """Test listing the blocklists and the allowlists separately."""
    filter_lists = await getattr(adguard.filtering, kind).list()

    assert len(filter_lists) == count
    assert next((f.url for f in filter_lists), None) == first_url


@pytest.mark.usefixtures("status")
async def test_get_filter_list(adguard: AdGuardHome) -> None:
    """Test finding a filter list by its exact URL."""
    filter_list = await adguard.filtering.blocklists.get(URL_EXAMPLE_ADS)

    assert filter_list is not None
    assert filter_list.name == "Example ads"
    assert not filter_list.enabled


@pytest.mark.usefixtures("status")
async def test_get_filter_list_matches_exactly(adguard: AdGuardHome) -> None:
    """Test a URL differing in case is a different filter list, like for the API."""
    assert await adguard.filtering.blocklists.get(URL_EXAMPLE_ADS.lower()) is None


@pytest.mark.parametrize(
    ("kind", "allowlist"), [("blocklists", False), ("allowlists", True)]
)
async def test_add(
    responses: aiointercept, adguard: AdGuardHome, kind: str, allowlist: bool
) -> None:
    """Test adding a filter list tells the API which kind it is."""
    responses.post(
        URL_ADD,
        callback=expect_json(
            {
                "name": "Example",
                "url": "https://example.com/list.txt",
                "whitelist": allowlist,
            }
        ),
    )

    await getattr(adguard.filtering, kind).add(
        "https://example.com/list.txt", name="Example"
    )


@pytest.mark.parametrize(
    ("kind", "allowlist"), [("blocklists", False), ("allowlists", True)]
)
async def test_remove(
    responses: aiointercept, adguard: AdGuardHome, kind: str, allowlist: bool
) -> None:
    """Test removing a filter list tells the API which kind it is."""
    responses.post(
        URL_REMOVE,
        callback=expect_json(
            {"url": "https://example.com/list.txt", "whitelist": allowlist}
        ),
    )

    await getattr(adguard.filtering, kind).remove("https://example.com/list.txt")


@pytest.mark.parametrize(("method", "enabled"), [("enable", True), ("disable", False)])
@pytest.mark.usefixtures("status")
async def test_enable_disable_filter_list(
    responses: aiointercept, adguard: AdGuardHome, method: str, enabled: bool
) -> None:
    """Test toggling a filter list keeps its name and URL."""
    responses.post(
        URL_SET,
        callback=expect_json(
            {
                "url": URL_EXAMPLE_ADS,
                "whitelist": False,
                "data": {
                    "name": "Example ads",
                    "url": URL_EXAMPLE_ADS,
                    "enabled": enabled,
                },
            }
        ),
    )

    await getattr(adguard.filtering.blocklists, method)(URL_EXAMPLE_ADS)


@pytest.mark.usefixtures("status")
async def test_update_filter_list(
    responses: aiointercept, adguard: AdGuardHome
) -> None:
    """Test renaming and moving a filter list keeps its enabled state."""
    responses.post(
        URL_SET,
        callback=expect_json(
            {
                "url": URL_DNS_FILTER,
                "whitelist": False,
                "data": {
                    "name": "Renamed",
                    "url": "https://example.com/moved.txt",
                    "enabled": True,
                },
            }
        ),
    )

    await adguard.filtering.blocklists.update(
        URL_DNS_FILTER, name="Renamed", new_url="https://example.com/moved.txt"
    )


@pytest.mark.usefixtures("status")
async def test_update_unknown_filter_list(adguard: AdGuardHome) -> None:
    """Test changing a filter list that does not exist raises an error."""
    with pytest.raises(AdGuardHomeError, match="no allowlist with URL"):
        await adguard.filtering.allowlists.enable(URL_DNS_FILTER)


@pytest.mark.parametrize(
    ("kind", "allowlist"), [("blocklists", False), ("allowlists", True)]
)
async def test_refresh(
    responses: aiointercept, adguard: AdGuardHome, kind: str, allowlist: bool
) -> None:
    """Test refreshing returns the number of filter lists that changed."""
    responses.post(
        URL_REFRESH,
        callback=expect_json({"whitelist": allowlist}, payload={"updated": 3}),
    )

    assert await getattr(adguard.filtering, kind).refresh() == 3


@pytest.mark.parametrize("payload", [{}, {"updated": "many"}])
async def test_refresh_unexpected_response(
    responses: aiointercept, adguard: AdGuardHome, payload: dict[str, Any]
) -> None:
    """Test a refresh response without a count raises an error."""
    responses.post(URL_REFRESH, status=200, payload=payload)

    with pytest.raises(AdGuardHomeError, match="Unexpected refresh response"):
        await adguard.filtering.blocklists.refresh()


@pytest.mark.usefixtures("status")
async def test_user_rules(adguard: AdGuardHome) -> None:
    """Test reading the custom filtering rules."""
    assert await adguard.filtering.user_rules() == (
        "||telemetry.example.com^",
        "! comment",
        "@@||allowed.example.com^",
    )


async def test_set_user_rules(responses: aiointercept, adguard: AdGuardHome) -> None:
    """Test replacing the custom filtering rules from any iterable."""
    responses.post(
        URL_SET_RULES, callback=expect_json({"rules": ["||a.example^", "||b.example^"]})
    )

    await adguard.filtering.set_user_rules(
        rule for rule in ("||a.example^", "||b.example^")
    )


async def test_check_host_filtered(
    responses: aiointercept,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
) -> None:
    """Test checking a host that a rule blocks."""
    responses.get(
        f"{URL_CHECK_HOST}?name=telemetry.example.com",
        status=200,
        payload=load_fixture("filtering_check_host_blocked"),
    )

    result = await adguard.filtering.check_host("telemetry.example.com")

    assert result.filtered
    assert result.reason is FilteringReason.FILTERED_BLOCKLIST
    assert result.rules[0].text == "||telemetry.example.com^"
    assert result.service_name is None
    assert result.cname is None
    assert result.ip_addresses == ()


async def test_check_host_rewrite(
    responses: aiointercept,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
) -> None:
    """Test checking a host for a client and record type, which is rewritten."""
    responses.get(
        f"{URL_CHECK_HOST}?name=nas&client=192.168.1.20&qtype=AAAA",
        status=200,
        payload=load_fixture("filtering_check_host_rewrite"),
    )

    result = await adguard.filtering.check_host(
        "nas", client="192.168.1.20", qtype="AAAA"
    )

    assert not result.filtered
    assert result.reason is FilteringReason.REWRITE
    assert result.rules == ()
    assert result.cname == "nas.lan"
    assert result.ip_addresses == ("192.168.1.5", "fd00::5")
