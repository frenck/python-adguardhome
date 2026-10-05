# pylint: disable=protected-access
"""Tests for `adguardhome.adguardhome`."""

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import patch

import aiohttp
import pytest
from aiointercept import CallbackResult, aiointercept
from awesomeversion import AwesomeVersion
from syrupy.assertion import SnapshotAssertion

from adguardhome import (
    AdGuardHome,
    AdGuardHomeAuthenticationError,
    AdGuardHomeConnectionError,
    AdGuardHomeConnectionTimeoutError,
    AdGuardHomeError,
    AdGuardHomeResponseError,
    AdGuardHomeUnsupportedError,
    Status,
)

from .conftest import FixtureLoader

URL_STATUS = "http://example.com:3000/control/status"
URL_PROTECTION = "http://example.com:3000/control/protection"


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://example.com:3000", URL_STATUS),
        ("http://example.com:3000/", URL_STATUS),
        ("https://example.com", "https://example.com/control/status"),
        ("https://example.com/adguard", "https://example.com/adguard/control/status"),
        ("https://example.com/adguard/", "https://example.com/adguard/control/status"),
        ("http://example.com:3000/?foo=bar#baz", URL_STATUS),
    ],
)
async def test_api_url(responses: aiointercept, url: str, expected: str) -> None:
    """Test the API URL is derived from the web interface URL."""
    responses.get(expected, status=200, payload={"ok": True})

    async with AdGuardHome(url) as adguard:
        assert await adguard._request("status") == {"ok": True}


@pytest.mark.parametrize("url", ["example.com", "ftp://example.com", "http://"])
def test_invalid_url(url: str) -> None:
    """Test an URL that is not HTTP or HTTPS is rejected."""
    with pytest.raises(ValueError, match="Invalid AdGuard Home URL"):
        AdGuardHome(url)


async def test_authenticated_request(responses: aiointercept) -> None:
    """Test credentials are sent using basic authentication."""

    def callback(_url: str, **kwargs: Any) -> CallbackResult:
        assert kwargs["headers"]["Authorization"] == aiohttp.encode_basic_auth(
            "frenck", "zerocool"
        )
        return CallbackResult(status=200, payload={"ok": True})

    responses.get(URL_STATUS, callback=callback)

    async with AdGuardHome(
        "http://example.com:3000",
        username="frenck",
        password="zerocool",  # noqa: S106
    ) as adguard:
        await adguard._request("status")


async def test_unauthenticated_request(
    responses: aiointercept, adguard: AdGuardHome
) -> None:
    """Test no authentication is sent without a username."""

    def callback(_url: str, **kwargs: Any) -> CallbackResult:
        assert "Authorization" not in kwargs["headers"]
        return CallbackResult(status=200, payload={"ok": True})

    responses.get(URL_STATUS, callback=callback)
    await adguard._request("status")


async def test_content_type_only_with_json(
    responses: aiointercept, adguard: AdGuardHome
) -> None:
    """Test a content type is only sent along with a JSON body."""
    seen: list[Any] = []

    def callback(_url: str, **kwargs: Any) -> CallbackResult:
        seen.append(kwargs["headers"].get("Content-Type"))
        return CallbackResult(status=200, body="OK\n", content_type="text/plain")

    responses.post(URL_PROTECTION, callback=callback, repeat=True)
    await adguard._request("protection", method="POST")
    await adguard._request("protection", method="POST", json={"enabled": True})

    assert seen == [None, "application/json"]


async def test_internal_session_is_closed(responses: aiointercept) -> None:
    """Test a session created by the client is closed with it."""
    responses.get(URL_STATUS, status=200, payload={"ok": True})

    async with AdGuardHome("http://example.com:3000") as adguard:
        await adguard._request("status")
        session = adguard._session

    assert session is not None
    assert session.closed


async def test_external_session_is_not_closed(
    responses: aiointercept, adguard: AdGuardHome
) -> None:
    """Test a session passed in by the caller is left open."""
    responses.get(URL_STATUS, status=200, payload={"ok": True})
    await adguard._request("status")

    await adguard.close()

    assert adguard._session is not None
    assert not adguard._session.closed


@pytest.mark.parametrize(
    ("content_type", "body"),
    [
        ("text/plain", "OK\n"),
        ("application/json", ""),
    ],
)
async def test_response_without_json(
    responses: aiointercept, adguard: AdGuardHome, content_type: str, body: str
) -> None:
    """Test a response without a JSON body returns None."""
    responses.post(URL_PROTECTION, status=200, body=body, content_type=content_type)
    assert await adguard._request("protection", method="POST") is None


async def test_response_invalid_json(
    responses: aiointercept, adguard: AdGuardHome
) -> None:
    """Test a response with broken JSON raises a response error."""
    responses.get(URL_STATUS, status=200, body="{", content_type="application/json")

    with pytest.raises(AdGuardHomeResponseError, match="invalid JSON"):
        await adguard._request("status")


async def test_timeout(adguard: AdGuardHome) -> None:
    """Test a timeout raises a timeout error, which is a connection error."""
    assert adguard._session is not None

    with (
        patch.object(adguard._session, "request", side_effect=TimeoutError),
        pytest.raises(AdGuardHomeConnectionTimeoutError) as excinfo,
    ):
        await adguard._request("status")

    assert isinstance(excinfo.value, AdGuardHomeConnectionError)


async def test_client_error(adguard: AdGuardHome) -> None:
    """Test an aiohttp client error raises a connection error."""
    assert adguard._session is not None

    with (
        patch.object(adguard._session, "request", side_effect=aiohttp.ClientError),
        pytest.raises(AdGuardHomeConnectionError),
    ):
        await adguard._request("status")


@pytest.mark.parametrize("status", [401, 403])
async def test_authentication_error(
    responses: aiointercept, adguard: AdGuardHome, status: int
) -> None:
    """Test rejected credentials raise an authentication error."""
    responses.get(URL_STATUS, status=status, body="Forbidden")

    with pytest.raises(AdGuardHomeAuthenticationError):
        await adguard._request("status")


async def test_unsupported_error(responses: aiointercept, adguard: AdGuardHome) -> None:
    """Test an unknown endpoint raises an unsupported error."""
    responses.get(URL_STATUS, status=404, body="404 page not found\n")

    with pytest.raises(AdGuardHomeUnsupportedError, match=r"v0\.107\.68") as excinfo:
        await adguard._request("status")

    assert excinfo.value.status == 404
    assert excinfo.value.body == "404 page not found"


@pytest.mark.parametrize("status", [400, 500, 503])
async def test_response_error(
    responses: aiointercept, adguard: AdGuardHome, status: int
) -> None:
    """Test an error response carries the status and message of AdGuard Home."""
    responses.get(URL_STATUS, status=status, body="interval: bad value\n")

    with pytest.raises(AdGuardHomeResponseError, match="bad value") as excinfo:
        await adguard._request("status")

    assert excinfo.value.status == status
    assert excinfo.value.body == "interval: bad value"


async def test_status(
    responses: aiointercept,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
    snapshot: SnapshotAssertion,
) -> None:
    """Test the server status is parsed into a model."""
    responses.get(URL_STATUS, status=200, payload=load_fixture("status"))

    status = await adguard.status()

    assert status == snapshot
    assert status.version == AwesomeVersion("v0.107.79")
    assert status.protection_enabled
    assert status.protection_resumes_in is None
    assert status.started_at == datetime(2025, 10, 3, 14, 0, 0, 123400, tzinfo=UTC)
    assert status.supported


async def test_status_paused(
    responses: aiointercept,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
) -> None:
    """Test the remaining time of a protection pause is a timedelta."""
    responses.get(URL_STATUS, status=200, payload=load_fixture("status_paused"))

    status = await adguard.status()

    assert not status.protection_enabled
    assert status.protection_resumes_in == timedelta(seconds=29.5)
    assert status.started_at is None
    assert status.supported


@pytest.mark.parametrize(
    ("version", "supported"),
    [
        ("v0.107.30", False),
        ("v0.107.67", False),
        ("v0.107.68", True),
        ("v0.108.0-b.1", True),
        ("v0.106.3", False),
        ("undefined", True),
    ],
)
async def test_status_supported(
    responses: aiointercept,
    adguard: AdGuardHome,
    load_fixture: FixtureLoader,
    version: str,
    supported: bool,
) -> None:
    """Test the version of AdGuard Home is checked against the minimum."""
    responses.get(
        URL_STATUS,
        status=200,
        payload=load_fixture("status") | {"version": version},
    )

    status = await adguard.status()

    assert status.supported is supported


def test_status_serializes_to_api_format(load_fixture: FixtureLoader) -> None:
    """Test a status serializes back to the format of the AdGuard Home API."""
    data = load_fixture("status_paused")
    status = Status.from_api(data)

    assert status.to_dict() == data
    assert Status.from_api(status.to_dict()) == status


def test_status_serializes_start_time(load_fixture: FixtureLoader) -> None:
    """Test the start time serializes back to Unix time in milliseconds."""
    data = load_fixture("status")
    status = Status.from_api(data)

    assert status.to_dict()["start_time"] == pytest.approx(data["start_time"])


async def test_status_unexpected_data(
    responses: aiointercept, adguard: AdGuardHome
) -> None:
    """Test a status response that does not fit the model raises an error."""
    responses.get(URL_STATUS, status=200, payload={"version": "v0.107.62"})

    with pytest.raises(AdGuardHomeError, match="Unexpected Status data"):
        await adguard.status()


async def test_enable_protection(responses: aiointercept, adguard: AdGuardHome) -> None:
    """Test enabling protection."""

    def callback(_url: str, **kwargs: Any) -> CallbackResult:
        assert kwargs["json"] == {"enabled": True}
        return CallbackResult(status=200, body="OK\n", content_type="text/plain")

    responses.post(URL_PROTECTION, callback=callback)
    await adguard.enable_protection()


async def test_disable_protection(
    responses: aiointercept, adguard: AdGuardHome
) -> None:
    """Test disabling protection until it is enabled again."""

    def callback(_url: str, **kwargs: Any) -> CallbackResult:
        assert kwargs["json"] == {"enabled": False}
        return CallbackResult(status=200, body="OK\n", content_type="text/plain")

    responses.post(URL_PROTECTION, callback=callback)
    await adguard.disable_protection()


async def test_disable_protection_with_duration(
    responses: aiointercept, adguard: AdGuardHome
) -> None:
    """Test pausing protection sends the duration in milliseconds."""

    def callback(_url: str, **kwargs: Any) -> CallbackResult:
        assert kwargs["json"] == {"enabled": False, "duration": 90_500}
        return CallbackResult(status=200, body="OK\n", content_type="text/plain")

    responses.post(URL_PROTECTION, callback=callback)
    await adguard.disable_protection(timedelta(minutes=1, seconds=30.5))


@pytest.mark.parametrize(
    "duration",
    [timedelta(0), timedelta(seconds=-1), timedelta(microseconds=999)],
)
async def test_disable_protection_invalid_duration(
    adguard: AdGuardHome, duration: timedelta
) -> None:
    """Test a duration shorter than a millisecond is rejected."""
    with pytest.raises(ValueError, match="must be positive"):
        await adguard.disable_protection(duration)
