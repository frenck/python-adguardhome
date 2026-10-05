"""Asynchronous Python client for the AdGuard Home API."""

from __future__ import annotations

import asyncio
import logging
import socket
from typing import TYPE_CHECKING, Any, Self

import aiohttp
import orjson
from yarl import URL

from ._model import MILLISECOND
from .access import AdGuardHomeAccess
from .blocked_services import AdGuardHomeBlockedServices
from .clients import AdGuardHomeClients
from .dhcp import AdGuardHomeDhcp
from .dns import AdGuardHomeDns
from .exceptions import (
    AdGuardHomeAuthenticationError,
    AdGuardHomeConnectionError,
    AdGuardHomeConnectionTimeoutError,
    AdGuardHomeResponseError,
    AdGuardHomeUnsupportedError,
)
from .filtering import AdGuardHomeFiltering
from .querylog import AdGuardHomeQueryLog
from .rewrite import AdGuardHomeRewrite
from .safesearch import AdGuardHomeSafeSearch
from .stats import AdGuardHomeStats
from .status import MINIMUM_VERSION, Status
from .tls import AdGuardHomeTls
from .toggle import Toggle
from .update import AdGuardHomeUpdate

if TYPE_CHECKING:
    from collections.abc import Mapping
    from datetime import timedelta

_LOGGER = logging.getLogger(__name__)


# pylint: disable-next=too-many-instance-attributes
class AdGuardHome:
    """Client for the AdGuard Home API."""

    # pylint: disable-next=too-many-arguments
    def __init__(  # noqa: PLR0913
        self,
        url: str | URL,
        *,
        username: str | None = None,
        password: str | None = None,
        request_timeout: float = 10,
        session: aiohttp.ClientSession | None = None,
        verify_ssl: bool = True,
    ) -> None:
        """Initialize the AdGuard Home client.

        Args:
        ----
            url: The URL of the AdGuard Home web interface, the same one you
                open in your browser. For example `http://192.168.1.2:3000`,
                or `https://example.com/adguard` behind a reverse proxy.
            username: Username, if AdGuard Home has authentication enabled.
            password: Password, if AdGuard Home has authentication enabled.
            request_timeout: Seconds to wait for a response from the API.
            session: Optional, shared, aiohttp client session.
            verify_ssl: Set to False when AdGuard Home uses a self-signed
                certificate.

        Raises:
        ------
            ValueError: The URL is not an HTTP or HTTPS URL, or it holds
                credentials.

        """
        self.url = URL(url)
        if self.url.scheme not in ("http", "https") or not self.url.host:
            msg = f"Invalid AdGuard Home URL: {url}"
            raise ValueError(msg)

        # Credentials in the URL would end up in logs and error messages.
        if self.url.user or self.url.password:
            msg = "Pass the username and password separately, not in the URL"
            raise ValueError(msg)

        # The API lives under /control, relative to the web interface.
        self._api_url = self.url.with_query(None).with_fragment(None) / "control"

        self._headers = {"Accept": "application/json"}
        if username:
            self._headers["Authorization"] = aiohttp.encode_basic_auth(
                username, password or ""
            )

        self._session = session
        self._close_session = False
        self.request_timeout = request_timeout
        self.verify_ssl = verify_ssl

        self.access = AdGuardHomeAccess(self._request)
        self.blocked_services = AdGuardHomeBlockedServices(self._request)
        self.clients = AdGuardHomeClients(self._request)
        self.dhcp = AdGuardHomeDhcp(self._request)
        self.dns = AdGuardHomeDns(self._request)
        self.filtering = AdGuardHomeFiltering(self._request)
        self.parental = Toggle(self._request, "parental")
        self.querylog = AdGuardHomeQueryLog(self._request)
        self.rewrite = AdGuardHomeRewrite(self._request)
        self.safebrowsing = Toggle(self._request, "safebrowsing")
        self.safesearch = AdGuardHomeSafeSearch(self._request)
        self.stats = AdGuardHomeStats(self._request)
        self.tls = AdGuardHomeTls(self._request)
        self.update = AdGuardHomeUpdate(self._request)

    async def _request(
        self,
        path: str,
        *,
        method: str = "GET",
        json: Any = None,
        params: Mapping[str, str] | None = None,
    ) -> Any:
        """Handle a request to the AdGuard Home API.

        Args:
        ----
            path: The API path, relative to `/control`. For example `status`.
            method: HTTP method to use for the request.
            json: Data to send as JSON with the request.
            params: Query parameters to send with the request.

        Returns:
        -------
            The decoded JSON response, or None when AdGuard Home confirmed an
            action, which it does with an empty response or a plain "OK".

        Raises:
        ------
            AdGuardHomeConnectionError: AdGuard Home could not be reached.
            AdGuardHomeConnectionTimeoutError: AdGuard Home did not respond
                in time.
            AdGuardHomeAuthenticationError: The credentials were rejected.
            AdGuardHomeUnsupportedError: AdGuard Home does not know the
                endpoint, which means it is too old for this library.
            AdGuardHomeResponseError: AdGuard Home responded with an error,
                a redirect, JSON we could not decode, or something else than
                JSON or "OK", like the login page of a reverse proxy.

        """
        url = self._api_url / path

        if self._session is None:
            self._session = aiohttp.ClientSession()
            self._close_session = True

        if self._session.closed:
            msg = "The session to communicate with AdGuard Home is closed"
            raise AdGuardHomeConnectionError(msg)

        # Without a body, aiohttp would still add a content type header.
        # Only send one when there actually is JSON to send.
        skip_auto_headers = {"Content-Type"} if json is None else None

        _LOGGER.debug("%s %s", method, url)

        try:
            async with (
                asyncio.timeout(self.request_timeout),
                self._session.request(
                    method,
                    url,
                    headers=self._headers,
                    json=json,
                    params=params,
                    skip_auto_headers=skip_auto_headers,
                    ssl=self.verify_ssl,
                    # A redirect would send the request, including a TLS
                    # private key, on to wherever it points, also plain HTTP.
                    allow_redirects=False,
                    # A shared session may raise on errors itself, before we
                    # can tell an authentication error from a server error.
                    raise_for_status=False,
                ) as response,
            ):
                status = response.status
                content_type = response.headers.get("Content-Type", "")
                location = response.headers.get("Location", "")
                body = await response.read()
        except TimeoutError as exception:
            msg = "Timeout occurred while connecting to AdGuard Home"
            raise AdGuardHomeConnectionTimeoutError(msg) from exception
        except (aiohttp.ClientError, socket.gaierror) as exception:
            msg = "Error occurred while communicating with AdGuard Home"
            raise AdGuardHomeConnectionError(msg) from exception

        _LOGGER.debug("%s %s returned %s", method, url, status)

        # AdGuard Home sends its error messages as plain text.
        text = body.decode(errors="replace").strip()

        if status in (401, 403):
            msg = "AdGuard Home rejected the credentials"
            raise AdGuardHomeAuthenticationError(msg)

        if status == 404:
            msg = (
                f"AdGuard Home does not support /control/{path}, "
                f"version {MINIMUM_VERSION} or newer is required"
            )
            raise AdGuardHomeUnsupportedError(msg, status=status, body=text)

        if status >= 400:
            msg = f"AdGuard Home responded with HTTP {status}: {text}"
            raise AdGuardHomeResponseError(msg, status=status, body=text)

        if status >= 300:
            # Like with force HTTPS enabled, which redirects to HTTPS.
            msg = f"AdGuard Home redirects to {location}, use that URL instead"
            raise AdGuardHomeResponseError(msg, status=status, body=text)

        if "application/json" not in content_type:
            if text in ("", "OK"):
                return None

            msg = (
                "AdGuard Home responded with something else than JSON, "
                "check if the URL points to AdGuard Home"
            )
            raise AdGuardHomeResponseError(msg, status=status, body=text)

        if not body:
            return None

        try:
            return orjson.loads(body)  # pylint: disable=no-member
        except orjson.JSONDecodeError as exception:  # pylint: disable=no-member
            msg = "AdGuard Home responded with invalid JSON"
            raise AdGuardHomeResponseError(msg, status=status, body=text) from exception

    async def status(self) -> Status:
        """Return the status of the AdGuard Home server.

        Returns
        -------
            The server status, including its version and protection state.
            Use `Status.supported` to check if this library supports the
            version of the AdGuard Home server.

        """
        return Status.from_api(await self._request("status"))

    async def enable_protection(self) -> None:
        """Enable AdGuard Home protection.

        This also resumes protection that is paused.
        """
        await self._request("protection", method="POST", json={"enabled": True})

    async def disable_protection(self, duration: timedelta | None = None) -> None:
        """Disable AdGuard Home protection.

        Args:
        ----
            duration: How long to pause protection for. AdGuard Home enables
                protection again by itself afterwards. When None, protection
                stays disabled until it is enabled again.

        Raises:
        ------
            ValueError: The duration is not positive.

        """
        payload: dict[str, bool | int] = {"enabled": False}

        if duration is not None:
            if duration < MILLISECOND:
                msg = "The duration to disable protection for must be positive"
                raise ValueError(msg)
            payload["duration"] = duration // MILLISECOND

        await self._request("protection", method="POST", json=payload)

    async def close(self) -> None:
        """Close the client session, if we opened it."""
        if self._session and self._close_session:
            await self._session.close()

    async def __aenter__(self) -> Self:
        """Async enter.

        Returns
        -------
            The AdGuard Home client.

        """
        return self

    async def __aexit__(self, *_exc_info: object) -> None:
        """Async exit.

        Args:
        ----
            _exc_info: Exception type, value, and traceback.

        """
        await self.close()
