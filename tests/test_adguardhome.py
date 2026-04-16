"""Tests for `adguardhome.adguardhome`."""

from unittest.mock import patch

import aiohttp
import pytest
from aioresponses import aioresponses

from adguardhome import AdGuardHome
from adguardhome.exceptions import AdGuardHomeConnectionError, AdGuardHomeError

URL_ROOT = "http://example.com:3000/"
URL_STATUS = "http://example.com:3000/control/status"
URL_DNS_CONFIG = "http://example.com:3000/control/dns_config"


async def test_json_request(responses: aioresponses, adguard: AdGuardHome) -> None:
    """Test JSON response is handled correctly."""
    responses.get(URL_ROOT, status=200, payload={"status": "ok"})
    assert (await adguard.request("/"))["status"] == "ok"


async def test_close_external_session(
    responses: aioresponses,
    adguard: AdGuardHome,
) -> None:
    """Test that closing a client with an external session does not close it."""
    responses.get(URL_ROOT, status=200, payload={"status": "ok"})
    await adguard.request("/")

    await adguard.close()

    assert adguard._session is not None  # pylint: disable=protected-access
    assert not adguard._session.closed  # pylint: disable=protected-access


async def test_authenticated_request(responses: aioresponses) -> None:
    """Test authenticated JSON response is handled correctly."""
    responses.get(URL_ROOT, status=200, payload={"status": "ok"})

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome(
            "example.com",
            username="frenck",
            password="zerocool",  # noqa: S106
            session=session,
        )
        assert (await adguard.request("/"))["status"] == "ok"


async def test_text_request(responses: aioresponses, adguard: AdGuardHome) -> None:
    """Test non-JSON response is handled correctly."""
    responses.get(URL_ROOT, status=200, body="OK", content_type="text/plain")
    assert await adguard.request("/") == {"message": "OK"}


async def test_internal_session(responses: aioresponses) -> None:
    """Test that an internal client session is created when none is passed."""
    responses.get(URL_ROOT, status=200, payload={"status": "ok"})

    async with AdGuardHome("example.com") as adguard:
        assert (await adguard.request("/"))["status"] == "ok"


async def test_post_request(responses: aioresponses, adguard: AdGuardHome) -> None:
    """Test POST requests are handled correctly."""
    responses.post(URL_ROOT, status=200, body="OK", content_type="text/plain")
    assert await adguard.request("/", method="POST") == {"message": "OK"}


async def test_request_port(responses: aioresponses) -> None:
    """Test AdGuard Home running on a non-standard port."""
    responses.get(
        "http://example.com:3333/",
        status=200,
        body="OMG PUPPIES!",
        content_type="text/plain",
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", port=3333, session=session)
        assert await adguard.request("/") == {"message": "OMG PUPPIES!"}


async def test_request_base_path(responses: aioresponses) -> None:
    """Test AdGuard Home running on a non-default base path."""
    responses.get(
        "http://example.com:3000/admin/status",
        status=200,
        body="OMG PUPPIES!",
        content_type="text/plain",
    )

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", base_path="/admin", session=session)
        assert await adguard.request("status") == {"message": "OMG PUPPIES!"}


async def test_timeout(responses: aioresponses) -> None:
    """Test request timeouts are raised as connection errors."""
    responses.get(URL_ROOT, exception=TimeoutError())

    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session, request_timeout=1)
        with pytest.raises(AdGuardHomeConnectionError):
            await adguard.request("/")


async def test_client_error() -> None:
    """Test aiohttp client errors are raised as connection errors."""
    async with aiohttp.ClientSession() as session:
        adguard = AdGuardHome("example.com", session=session)
        with (
            patch.object(session, "request", side_effect=aiohttp.ClientError),
            pytest.raises(AdGuardHomeConnectionError),
        ):
            await adguard.request("/")


@pytest.mark.parametrize(
    ("status", "payload", "body"),
    [
        (404, None, "OMG PUPPIES!"),
        (500, {"status": "nok"}, None),
    ],
)
async def test_http_error(
    responses: aioresponses,
    adguard: AdGuardHome,
    status: int,
    payload: dict[str, str] | None,
    body: str | None,
) -> None:
    """Test HTTP error responses are raised as AdGuardHomeError."""
    if payload is not None:
        responses.get(URL_ROOT, status=status, payload=payload)
    else:
        responses.get(URL_ROOT, status=status, body=body, content_type="text/plain")

    with pytest.raises(AdGuardHomeError):
        await adguard.request("/")


@pytest.mark.parametrize("enabled", [True, False])
async def test_protection_enabled(
    responses: aioresponses,
    adguard: AdGuardHome,
    enabled: bool,
) -> None:
    """Test reporting AdGuard Home protection status."""
    responses.get(URL_STATUS, status=200, payload={"protection_enabled": enabled})
    assert await adguard.protection_enabled() is enabled


async def test_enable_protection(
    responses: aioresponses,
    adguard: AdGuardHome,
) -> None:
    """Test enabling AdGuard Home protection."""
    responses.post(URL_DNS_CONFIG, status=200, content_type="text/plain")
    await adguard.enable_protection()


@pytest.mark.parametrize("status", [400, 500])
async def test_enable_protection_error(
    responses: aioresponses,
    adguard: AdGuardHome,
    status: int,
) -> None:
    """Test enabling protection fails on HTTP error."""
    responses.post(URL_DNS_CONFIG, status=status, content_type="text/plain")
    with pytest.raises(AdGuardHomeError):
        await adguard.enable_protection()


async def test_disable_protection(
    responses: aioresponses,
    adguard: AdGuardHome,
) -> None:
    """Test disabling AdGuard Home protection."""
    responses.post(URL_DNS_CONFIG, status=200, content_type="text/plain")
    await adguard.disable_protection()


@pytest.mark.parametrize("status", [400, 500])
async def test_disable_protection_error(
    responses: aioresponses,
    adguard: AdGuardHome,
    status: int,
) -> None:
    """Test disabling protection fails on HTTP error."""
    responses.post(URL_DNS_CONFIG, status=status, content_type="text/plain")
    with pytest.raises(AdGuardHomeError):
        await adguard.disable_protection()


async def test_version(responses: aioresponses, adguard: AdGuardHome) -> None:
    """Test requesting AdGuard Home instance version."""
    responses.get(URL_STATUS, status=200, payload={"version": "1.1"})
    assert await adguard.version() == "1.1"
