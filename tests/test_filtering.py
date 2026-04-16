"""Tests for `adguardhome.filtering`."""

from typing import Any

import pytest
from aioresponses import CallbackResult, aioresponses

from adguardhome import AdGuardHome
from adguardhome.exceptions import AdGuardHomeError

URL_STATUS = "http://example.com:3000/control/filtering/status"
URL_CONFIG = "http://example.com:3000/control/filtering/config"
URL_ADD = "http://example.com:3000/control/filtering/add_url"
URL_REMOVE = "http://example.com:3000/control/filtering/remove_url"
URL_SET = "http://example.com:3000/control/filtering/set_url"
URL_REFRESH_FALSE = "http://example.com:3000/control/filtering/refresh?force=false"
URL_REFRESH_TRUE = "http://example.com:3000/control/filtering/refresh?force=true"

FILTER_TEST = "https://example.com/1.txt"
FILTER_LIST_WITH_NAME = {
    "filters": [{"url": "https://EXAMPLE.com/1.txt", "name": "test"}],
}


@pytest.mark.parametrize("enabled", [True, False])
async def test_enabled(
    responses: aioresponses,
    adguard: AdGuardHome,
    enabled: bool,
) -> None:
    """Test reporting filtering status."""
    responses.get(URL_STATUS, status=200, payload={"enabled": enabled})
    assert await adguard.filtering.enabled() is enabled


async def test_enable(responses: aioresponses, adguard: AdGuardHome) -> None:
    """Test enabling filtering."""

    def callback(_url: str, **kwargs: object) -> CallbackResult:
        assert kwargs["json"] == {"enabled": True, "interval": 1}
        return CallbackResult(status=200, content_type="text/plain")

    responses.get(URL_STATUS, status=200, payload={"interval": 1})
    responses.post(URL_CONFIG, callback=callback)

    await adguard.filtering.enable()


@pytest.mark.parametrize("status", [400, 500])
async def test_enable_error(
    responses: aioresponses,
    adguard: AdGuardHome,
    status: int,
) -> None:
    """Test enabling filtering fails on HTTP error."""
    responses.get(URL_STATUS, status=200, payload={"interval": 1})
    responses.post(URL_CONFIG, status=status, content_type="text/plain")

    with pytest.raises(AdGuardHomeError):
        await adguard.filtering.enable()


async def test_disable(responses: aioresponses, adguard: AdGuardHome) -> None:
    """Test disabling filtering."""

    def callback(_url: str, **kwargs: object) -> CallbackResult:
        assert kwargs["json"] == {"enabled": False, "interval": 1}
        return CallbackResult(status=200, content_type="text/plain")

    responses.get(URL_STATUS, status=200, payload={"interval": 1})
    responses.post(URL_CONFIG, callback=callback)

    await adguard.filtering.disable()


@pytest.mark.parametrize("status", [400, 500])
async def test_disable_error(
    responses: aioresponses,
    adguard: AdGuardHome,
    status: int,
) -> None:
    """Test disabling filtering fails on HTTP error."""
    responses.get(URL_STATUS, status=200, payload={"interval": 1})
    responses.post(URL_CONFIG, status=status, content_type="text/plain")

    with pytest.raises(AdGuardHomeError):
        await adguard.filtering.disable()


async def test_interval_get(
    responses: aioresponses,
    adguard: AdGuardHome,
) -> None:
    """Test reading the filtering retention interval."""
    responses.get(URL_STATUS, status=200, payload={"interval": 7})
    assert await adguard.filtering.interval() == 7


async def test_interval_set(
    responses: aioresponses,
    adguard: AdGuardHome,
) -> None:
    """Test setting the filtering retention interval."""

    def callback(_url: str, **kwargs: object) -> CallbackResult:
        assert kwargs["json"] == {"enabled": True, "interval": 1}
        return CallbackResult(status=200, content_type="text/plain")

    responses.get(URL_STATUS, status=200, payload={"enabled": True})
    responses.post(URL_CONFIG, callback=callback)

    assert await adguard.filtering.interval(interval=1) == 1


@pytest.mark.parametrize("status", [400, 500])
async def test_interval_set_error(
    responses: aioresponses,
    adguard: AdGuardHome,
    status: int,
) -> None:
    """Test setting the filtering retention interval fails on HTTP error."""
    responses.get(URL_STATUS, status=200, payload={"enabled": True})
    responses.post(URL_CONFIG, status=status, content_type="text/plain")

    with pytest.raises(AdGuardHomeError):
        await adguard.filtering.interval(interval=1)


@pytest.mark.parametrize(
    ("payload", "allowlist", "expected"),
    [
        (
            {"filters": [{"rules_count": 99}, {"rules_count": 1}]},
            False,
            100,
        ),
        ({"filters": []}, False, 0),
        (
            {"whitelist_filters": [{"rules_count": 98}, {"rules_count": 1}]},
            True,
            99,
        ),
        ({"whitelist_filters": None}, True, 0),
    ],
)
async def test_rules_count(
    responses: aioresponses,
    adguard: AdGuardHome,
    payload: dict[str, Any],
    allowlist: bool,
    expected: int,
) -> None:
    """Test computing the total rules count across filter lists."""
    responses.get(URL_STATUS, status=200, payload=payload)
    assert await adguard.filtering.rules_count(allowlist=allowlist) == expected


async def test_add_url(responses: aioresponses, adguard: AdGuardHome) -> None:
    """Test adding a filter subscription."""

    def callback(_url: str, **kwargs: object) -> CallbackResult:
        assert kwargs["json"] == {
            "name": "Example",
            "url": FILTER_TEST,
            "whitelist": False,
        }
        return CallbackResult(
            status=200, body="OK 12345 filters added", content_type="text/plain"
        )

    responses.post(URL_ADD, callback=callback)
    await adguard.filtering.add_url(name="Example", url=FILTER_TEST, allowlist=False)


@pytest.mark.parametrize("status", [400, 500])
async def test_add_url_error(
    responses: aioresponses,
    adguard: AdGuardHome,
    status: int,
) -> None:
    """Test adding a filter subscription fails on HTTP error."""
    responses.post(
        URL_ADD, status=status, body="Invalid URL", content_type="text/plain"
    )
    with pytest.raises(AdGuardHomeError):
        await adguard.filtering.add_url(
            name="Example", url=FILTER_TEST, allowlist=False
        )


async def test_remove_url(responses: aioresponses, adguard: AdGuardHome) -> None:
    """Test removing a filter subscription."""

    def callback(_url: str, **kwargs: object) -> CallbackResult:
        assert kwargs["json"] == {"url": FILTER_TEST, "whitelist": False}
        return CallbackResult(status=200, body="OK", content_type="text/plain")

    responses.post(URL_REMOVE, callback=callback)
    await adguard.filtering.remove_url(allowlist=False, url=FILTER_TEST)


@pytest.mark.parametrize("status", [400, 500])
async def test_remove_url_error(
    responses: aioresponses,
    adguard: AdGuardHome,
    status: int,
) -> None:
    """Test removing a filter subscription fails on HTTP error."""
    responses.post(
        URL_REMOVE, status=status, body="Invalid URL", content_type="text/plain"
    )
    with pytest.raises(AdGuardHomeError):
        await adguard.filtering.remove_url(allowlist=False, url=FILTER_TEST)


async def test_enable_url(responses: aioresponses, adguard: AdGuardHome) -> None:
    """Test enabling a filter subscription."""

    def callback(_url: str, **kwargs: object) -> CallbackResult:
        assert kwargs["json"] == {
            "url": FILTER_TEST,
            "whitelist": False,
            "data": {"enabled": True, "url": FILTER_TEST, "name": "test"},
        }
        return CallbackResult(status=200, body="OK", content_type="text/plain")

    responses.get(URL_STATUS, status=200, payload=FILTER_LIST_WITH_NAME)
    responses.post(URL_SET, callback=callback)

    await adguard.filtering.enable_url(allowlist=False, url=FILTER_TEST)


@pytest.mark.parametrize("status", [400, 500])
async def test_enable_url_error(
    responses: aioresponses,
    adguard: AdGuardHome,
    status: int,
) -> None:
    """Test enabling a filter subscription fails on HTTP error."""
    responses.get(URL_STATUS, status=200, payload=FILTER_LIST_WITH_NAME)
    responses.post(URL_SET, status=status, content_type="text/plain")

    with pytest.raises(AdGuardHomeError):
        await adguard.filtering.enable_url(allowlist=False, url=FILTER_TEST)


async def test_disable_url(responses: aioresponses, adguard: AdGuardHome) -> None:
    """Test disabling a filter subscription."""

    def callback(_url: str, **kwargs: object) -> CallbackResult:
        assert kwargs["json"] == {
            "url": FILTER_TEST,
            "whitelist": False,
            "data": {"enabled": False, "name": "test", "url": FILTER_TEST},
        }
        return CallbackResult(status=200, content_type="text/plain")

    responses.get(URL_STATUS, status=200, payload=FILTER_LIST_WITH_NAME)
    responses.post(URL_SET, callback=callback)

    await adguard.filtering.disable_url(allowlist=False, url=FILTER_TEST)


@pytest.mark.parametrize("status", [400, 500])
async def test_disable_url_error(
    responses: aioresponses,
    adguard: AdGuardHome,
    status: int,
) -> None:
    """Test disabling a filter subscription fails on HTTP error."""
    responses.get(URL_STATUS, status=200, payload=FILTER_LIST_WITH_NAME)
    responses.post(URL_SET, status=status, content_type="text/plain")

    with pytest.raises(AdGuardHomeError):
        await adguard.filtering.disable_url(allowlist=False, url=FILTER_TEST)


@pytest.mark.parametrize(
    ("payload", "allowlist", "expected"),
    [
        (
            {"filters": [{"url": "https://EXAMPLE.com/1.txt", "enabled": True}]},
            False,
            True,
        ),
        (
            {"filters": [{"url": "https://EXAMPLE.com/1.txt", "enabled": False}]},
            False,
            False,
        ),
        (
            {"filters": [{"url": "https://EXAMPLE.com/1.txt", "enabled": True}]},
            True,
            False,
        ),
        (
            {
                "whitelist_filters": [
                    {"url": "https://EXAMPLE.com/1.txt", "enabled": True},
                ],
            },
            True,
            True,
        ),
    ],
)
async def test_url_enabled(
    responses: aioresponses,
    adguard: AdGuardHome,
    payload: dict[str, Any],
    allowlist: bool,
    expected: bool,
) -> None:
    """Test checking whether a filter subscription is enabled."""
    responses.get(URL_STATUS, status=200, payload=payload)
    assert (
        await adguard.filtering.url_enabled(allowlist=allowlist, url=FILTER_TEST)
        is expected
    )


async def test_refresh(responses: aioresponses, adguard: AdGuardHome) -> None:
    """Test refreshing filter subscriptions."""

    def blocklist_callback(_url: str, **kwargs: object) -> CallbackResult:
        assert kwargs["json"] == {"whitelist": False}
        return CallbackResult(status=200, content_type="text/plain")

    def whitelist_callback(_url: str, **kwargs: object) -> CallbackResult:
        assert kwargs["json"] == {"whitelist": True}
        return CallbackResult(status=200, content_type="text/plain")

    responses.post(URL_REFRESH_FALSE, callback=blocklist_callback)
    responses.post(URL_REFRESH_FALSE, callback=whitelist_callback)
    responses.post(URL_REFRESH_TRUE, status=200, body="OK", content_type="text/plain")

    await adguard.filtering.refresh(allowlist=False, force=False)
    await adguard.filtering.refresh(allowlist=True, force=False)
    await adguard.filtering.refresh(allowlist=False, force=True)


@pytest.mark.parametrize("status", [400, 500])
async def test_refresh_error(
    responses: aioresponses,
    adguard: AdGuardHome,
    status: int,
) -> None:
    """Test refreshing filter subscriptions fails on HTTP error."""
    responses.post(
        URL_REFRESH_FALSE, status=status, body="Not OK", content_type="text/plain"
    )
    with pytest.raises(AdGuardHomeError):
        await adguard.filtering.refresh(allowlist=False, force=False)
