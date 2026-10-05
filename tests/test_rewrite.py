"""Tests for `adguardhome.rewrite`."""

from typing import Any

import pytest
from aiointercept import CallbackResult, aiointercept
from syrupy.assertion import SnapshotAssertion
from yarl import URL

from adguardhome import AdGuardHome, RewriteConfig, RewriteRule

from .conftest import FixtureLoader

URL_BASE = "http://example.com:3000/control/rewrite"
URL_LIST = f"{URL_BASE}/list"
URL_ADD = f"{URL_BASE}/add"
URL_UPDATE = f"{URL_BASE}/update"
URL_DELETE = f"{URL_BASE}/delete"
URL_SETTINGS = f"{URL_BASE}/settings"
URL_SETTINGS_UPDATE = f"{URL_BASE}/settings/update"


def expect_json(expected: Any) -> Any:
    """Return a callback asserting the JSON body of the request."""

    def callback(_url: URL, **kwargs: Any) -> CallbackResult:
        assert kwargs["json"] == expected
        return CallbackResult(status=200, body="OK\n", content_type="text/plain")

    return callback


async def test_get(
    responses: aiointercept,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
    snapshot: SnapshotAssertion,
) -> None:
    """Test the DNS rewrite rules are parsed into models."""
    responses.get(URL_LIST, status=200, payload=load_fixture("rewrite_list"))

    rules = await adguard.rewrite.get()

    assert rules == snapshot
    assert rules == (
        RewriteRule(domain="*.example.com", answer="192.168.1.2"),
        RewriteRule(domain="ads.tracker.io", answer="127.0.0.1", enabled=False),
    )


async def test_get_empty(responses: aiointercept, adguard: AdGuardHome) -> None:
    """Test AdGuard Home without rules, which sends null."""
    responses.get(URL_LIST, status=200, payload=None)

    assert await adguard.rewrite.get() == ()


@pytest.mark.parametrize("enabled", [True, False])
async def test_add(
    responses: aiointercept, adguard: AdGuardHome, enabled: bool
) -> None:
    """Test adding a DNS rewrite rule, applied or not."""
    responses.post(
        URL_ADD,
        callback=expect_json(
            {"domain": "*.example.com", "answer": "192.168.1.2", "enabled": enabled}
        ),
    )

    await adguard.rewrite.add("*.example.com", "192.168.1.2", enabled=enabled)


async def test_update(responses: aiointercept, adguard: AdGuardHome) -> None:
    """Test changing the answer of a rule keeps its enabled state."""
    responses.put(
        URL_UPDATE,
        callback=expect_json(
            {
                "target": {"domain": "nas.lan", "answer": "192.168.1.5"},
                "update": {"domain": "nas.lan", "answer": "192.168.1.6"},
            }
        ),
    )

    await adguard.rewrite.update("nas.lan", "192.168.1.5", new_answer="192.168.1.6")


@pytest.mark.parametrize("enabled", [True, False])
async def test_update_enabled(
    responses: aiointercept, adguard: AdGuardHome, enabled: bool
) -> None:
    """Test enabling or disabling a rule keeps its domain and answer."""
    responses.put(
        URL_UPDATE,
        callback=expect_json(
            {
                "target": {"domain": "nas.lan", "answer": "192.168.1.5"},
                "update": {
                    "domain": "nas.lan",
                    "answer": "192.168.1.5",
                    "enabled": enabled,
                },
            }
        ),
    )

    await adguard.rewrite.update("nas.lan", "192.168.1.5", enabled=enabled)


async def test_update_domain(responses: aiointercept, adguard: AdGuardHome) -> None:
    """Test moving a rule to a new domain."""
    responses.put(
        URL_UPDATE,
        callback=expect_json(
            {
                "target": {"domain": "nas.lan", "answer": "192.168.1.5"},
                "update": {"domain": "storage.lan", "answer": "192.168.1.5"},
            }
        ),
    )

    await adguard.rewrite.update("nas.lan", "192.168.1.5", new_domain="storage.lan")


async def test_remove(responses: aiointercept, adguard: AdGuardHome) -> None:
    """Test removing a DNS rewrite rule by its domain and answer."""
    responses.post(
        URL_DELETE,
        callback=expect_json({"domain": "*.example.com", "answer": "192.168.1.2"}),
    )

    await adguard.rewrite.remove("*.example.com", "192.168.1.2")


async def test_config(responses: aiointercept, adguard: AdGuardHome) -> None:
    """Test reading whether rewrites are applied at all."""
    responses.get(URL_SETTINGS, status=200, payload={"enabled": True})

    assert await adguard.rewrite.config() == RewriteConfig(enabled=True)


@pytest.mark.parametrize(("method", "enabled"), [("enable", True), ("disable", False)])
async def test_enable_disable(
    responses: aiointercept, adguard: AdGuardHome, method: str, enabled: bool
) -> None:
    """Test turning all rewrites on and off."""
    responses.get(URL_SETTINGS, status=200, payload={"enabled": not enabled})
    responses.put(URL_SETTINGS_UPDATE, callback=expect_json({"enabled": enabled}))

    await getattr(adguard.rewrite, method)()
