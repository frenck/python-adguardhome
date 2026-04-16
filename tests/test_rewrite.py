"""Tests for `adguardhome.rewrite`."""

import pytest
from aioresponses import CallbackResult, aioresponses
from syrupy.assertion import SnapshotAssertion

from adguardhome import AdGuardHome, RewriteRule
from adguardhome.exceptions import AdGuardHomeError

from .conftest import FixtureLoader

URL_LIST = "http://example.com:3000/control/rewrite/list"
URL_ADD = "http://example.com:3000/control/rewrite/add"
URL_DELETE = "http://example.com:3000/control/rewrite/delete"


async def test_list_rules(
    responses: aioresponses,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
) -> None:
    """Test listing all DNS rewrite rules."""
    responses.get(URL_LIST, status=200, payload=load_fixture("rewrite_list"))

    result = await adguard.rewrite.list_rules()

    assert len(result) == 2
    assert result[0] == RewriteRule(
        domain="*.example.com", answer="192.168.1.2", enabled=True
    )
    assert result[1].enabled is False


async def test_list_rules_snapshot(
    responses: aioresponses,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
    snapshot: SnapshotAssertion,
) -> None:
    """Test rewrite rule parsing matches snapshot."""
    responses.get(URL_LIST, status=200, payload=load_fixture("rewrite_list"))
    assert await adguard.rewrite.list_rules() == snapshot


async def test_list_rules_empty(
    responses: aioresponses,
    adguard: AdGuardHome,
) -> None:
    """Test listing rules returns empty list when none exist."""
    responses.get(URL_LIST, status=200, payload=[])
    assert await adguard.rewrite.list_rules() == []


async def test_add(
    responses: aioresponses,
    adguard: AdGuardHome,
) -> None:
    """Test adding a DNS rewrite rule."""

    def callback(_url: str, **kwargs: object) -> CallbackResult:
        assert kwargs["json"] == {
            "domain": "*.example.com",
            "answer": "192.168.1.2",
        }
        return CallbackResult(status=200, content_type="text/plain")

    responses.post(URL_ADD, callback=callback)
    await adguard.rewrite.add("*.example.com", "192.168.1.2")


@pytest.mark.parametrize("status", [400, 500])
async def test_add_error(
    responses: aioresponses,
    adguard: AdGuardHome,
    status: int,
) -> None:
    """Test adding a DNS rewrite rule fails on HTTP error."""
    responses.post(URL_ADD, status=status, body="Error", content_type="text/plain")
    with pytest.raises(AdGuardHomeError):
        await adguard.rewrite.add("*.example.com", "192.168.1.2")


async def test_delete(
    responses: aioresponses,
    adguard: AdGuardHome,
) -> None:
    """Test deleting a DNS rewrite rule."""

    def callback(_url: str, **kwargs: object) -> CallbackResult:
        assert kwargs["json"] == {
            "domain": "*.example.com",
            "answer": "192.168.1.2",
        }
        return CallbackResult(status=200, content_type="text/plain")

    responses.post(URL_DELETE, callback=callback)
    await adguard.rewrite.delete("*.example.com", "192.168.1.2")


@pytest.mark.parametrize("status", [400, 500])
async def test_delete_error(
    responses: aioresponses,
    adguard: AdGuardHome,
    status: int,
) -> None:
    """Test deleting a DNS rewrite rule fails on HTTP error."""
    responses.post(URL_DELETE, status=status, body="Error", content_type="text/plain")
    with pytest.raises(AdGuardHomeError):
        await adguard.rewrite.delete("*.example.com", "192.168.1.2")
