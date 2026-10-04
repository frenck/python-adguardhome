"""Tests for `adguardhome.rewrite`."""

from typing import Any

from aiointercept import CallbackResult, aiointercept
from syrupy.assertion import SnapshotAssertion
from yarl import URL

from adguardhome import AdGuardHome, RewriteRule

from .conftest import FixtureLoader

URL_LIST = "http://example.com:3000/control/rewrite/list"
URL_ADD = "http://example.com:3000/control/rewrite/add"
URL_DELETE = "http://example.com:3000/control/rewrite/delete"


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


async def test_get_before_enabled(
    responses: aiointercept, adguard: AdGuardHome
) -> None:
    """Test rules from before per-rule `enabled` count as enabled."""
    responses.get(
        URL_LIST,
        status=200,
        payload=[{"domain": "nas.lan", "answer": "192.168.1.5"}],
    )

    (rule,) = await adguard.rewrite.get()

    assert rule.enabled


async def test_get_empty(responses: aiointercept, adguard: AdGuardHome) -> None:
    """Test AdGuard Home without rules, which sends null."""
    responses.get(URL_LIST, status=200, payload=None)

    assert await adguard.rewrite.get() == ()


async def test_add(responses: aiointercept, adguard: AdGuardHome) -> None:
    """Test adding a DNS rewrite rule."""

    def callback(_url: URL, **kwargs: Any) -> CallbackResult:
        assert kwargs["json"] == {"domain": "*.example.com", "answer": "192.168.1.2"}
        return CallbackResult(status=200, body="OK\n", content_type="text/plain")

    responses.post(URL_ADD, callback=callback)

    await adguard.rewrite.add("*.example.com", "192.168.1.2")


async def test_remove(responses: aiointercept, adguard: AdGuardHome) -> None:
    """Test removing a DNS rewrite rule by its domain and answer."""

    def callback(_url: URL, **kwargs: Any) -> CallbackResult:
        assert kwargs["json"] == {"domain": "*.example.com", "answer": "192.168.1.2"}
        return CallbackResult(status=200, body="OK\n", content_type="text/plain")

    responses.post(URL_DELETE, callback=callback)

    await adguard.rewrite.remove("*.example.com", "192.168.1.2")
