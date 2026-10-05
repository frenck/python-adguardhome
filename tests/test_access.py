"""Tests for `adguardhome.access`."""

from dataclasses import replace
from typing import Any

from aiointercept import CallbackResult, aiointercept
from yarl import URL

from adguardhome import AccessConfig, AdGuardHome

URL_LIST = "http://example.com:3000/control/access/list"
URL_SET = "http://example.com:3000/control/access/set"


async def test_config(responses: aiointercept, adguard: AdGuardHome) -> None:
    """Test the access lists are parsed, with null lists as empty."""
    responses.get(
        URL_LIST,
        status=200,
        payload={
            "allowed_clients": None,
            "disallowed_clients": ["203.0.113.0/24"],
            "blocked_hosts": ["version.bind", "id.server", "hostname.bind"],
        },
    )

    config = await adguard.access.config()

    assert config == AccessConfig(
        disallowed_clients=("203.0.113.0/24",),
        blocked_hosts=("version.bind", "id.server", "hostname.bind"),
    )


async def test_set_config(responses: aiointercept, adguard: AdGuardHome) -> None:
    """Test the access lists are sent in full, including empty ones."""

    def callback(_url: URL, **kwargs: Any) -> CallbackResult:
        assert kwargs["json"] == {
            "allowed_clients": ["192.168.1.0/24"],
            "disallowed_clients": [],
            "blocked_hosts": ["version.bind"],
        }
        return CallbackResult(status=200, body="OK\n", content_type="text/plain")

    responses.post(URL_SET, callback=callback)

    await adguard.access.set_config(
        replace(
            AccessConfig(blocked_hosts=("version.bind",)),
            allowed_clients=("192.168.1.0/24",),
        )
    )
