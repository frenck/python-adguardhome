"""Asynchronous Python client for the AdGuard Home API."""

from __future__ import annotations

import asyncio
import json
import socket
from typing import TYPE_CHECKING, Any, Self

import aiohttp
from yarl import URL

from .exceptions import AdGuardHomeConnectionError, AdGuardHomeError
from .filtering import AdGuardHomeFiltering
from .parental import AdGuardHomeParental
from .querylog import AdGuardHomeQueryLog
from .safebrowsing import AdGuardHomeSafeBrowsing
from .safesearch import AdGuardHomeSafeSearch
from .stats import AdGuardHomeStats
from .update import AdGuardHomeUpdate

if TYPE_CHECKING:
    from collections.abc import Mapping


# pylint: disable=too-many-instance-attributes
class AdGuardHome:
    """Main class for handling connections with AdGuard Home."""

    # pylint: disable-next=too-many-arguments
    def __init__(  # noqa: PLR0913
        self,
        host: str,
        *,
        base_path: str = "/control",
        password: str | None = None,
        port: int = 3000,
        request_timeout: int = 10,
        session: aiohttp.client.ClientSession | None = None,
        tls: bool = False,
        username: str | None = None,
        verify_ssl: bool = True,
    ) -> None:
        """Initialize connection with AdGuard Home.

        Class constructor for setting up an AdGuard Home object to
        communicate with an AdGuard Home instance.

        Args:
        ----
            host: Hostname or IP address of the AdGuard Home instance.
            base_path: Base path of the API, usually `/control`, which is the default.
            password: Password for HTTP auth, if enabled.
            port: Port on which the API runs, usually 3000.
            request_timeout: Max timeout to wait for a response from the API.
            session: Optional, shared, aiohttp client session.
            tls: True, when TLS/SSL should be used.
            username: Username for HTTP auth, if enabled.
            verify_ssl: Can be set to false, when TLS with self-signed cert is used.

        """
        self._session = session
        self._close_session = False

        self.base_path = base_path
        self.host = host
        self.password = password
        self.port = port
        self.request_timeout = request_timeout
        self.tls = tls
        self.username = username
        self.verify_ssl = verify_ssl

        if self.base_path[-1] != "/":
            self.base_path += "/"

        self.filtering = AdGuardHomeFiltering(self)
        self.parental = AdGuardHomeParental(self)
        self.querylog = AdGuardHomeQueryLog(self)
        self.safebrowsing = AdGuardHomeSafeBrowsing(self)
        self.safesearch = AdGuardHomeSafeSearch(self)
        self.stats = AdGuardHomeStats(self)
        self.update = AdGuardHomeUpdate(self)

    # pylint: disable-next=too-many-arguments, too-many-locals, too-many-positional-arguments
    async def request(
        self,
        uri: str,
        method: str = "GET",
        data: Any | None = None,
        json_data: dict[str, Any] | None = None,
        params: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        """Handle a request to the AdGuard Home instance.

        Make a request against the AdGuard Home API and handles the response.

        Args:
        ----
            uri: The request URI on the AdGuard Home API to call.
            method: HTTP method to use for the request; e.g., GET, POST.
            data: RAW HTTP request data to send with the request.
            json_data: Dictionary of data to send as JSON with the request.
            params: Mapping of request parameters to send with the request.

        Returns:
        -------
            The response from the API. In case the response is a JSON response,
            the method will return a decoded JSON response as a Python
            dictionary. In other cases, it will return the RAW text response.

        Raises:
        ------
            AdGuardHomeConnectionError: An error occurred while communicating
                with the AdGuard Home instance (connection issues).
            AdGuardHomeError: An error occurred while processing the
                response from the AdGuard Home instance (invalid data).

        """
        scheme = "https" if self.tls else "http"
        url = URL.build(
            scheme=scheme, host=self.host, port=self.port, path=self.base_path
        ).join(URL(uri))

        auth = None
        if self.username and self.password:
            auth = aiohttp.BasicAuth(self.username, self.password)

        headers = {
            "Accept": "application/json, text/plain, */*",
        }

        if self._session is None:
            self._session = aiohttp.ClientSession()
            self._close_session = True

        skip_auto_headers = None
        if data is None and json_data is None:
            skip_auto_headers = {"Content-Type"}

        try:
            async with asyncio.timeout(self.request_timeout):
                response = await self._session.request(
                    method,
                    url,
                    auth=auth,
                    data=data,
                    json=json_data,
                    params=params,
                    headers=headers,
                    ssl=self.verify_ssl,
                    skip_auto_headers=skip_auto_headers,
                )
        except TimeoutError as exception:
            msg = "Timeout occurred while connecting to AdGuard Home instance."
            raise AdGuardHomeConnectionError(msg) from exception
        except (aiohttp.ClientError, socket.gaierror) as exception:
            msg = "Error occurred while communicating with AdGuard Home."
            raise AdGuardHomeConnectionError(msg) from exception

        content_type = response.headers.get("Content-Type", "")
        if response.status // 100 in [4, 5]:
            contents = await response.read()
            response.close()

            if content_type == "application/json":
                raise AdGuardHomeError(
                    response.status, json.loads(contents.decode("utf8"))
                )
            raise AdGuardHomeError(
                response.status, {"message": contents.decode("utf8")}
            )

        if "application/json" in content_type:
            return await response.json()

        text = await response.text()
        return {"message": text}

    async def protection_enabled(self) -> bool:
        """Return if AdGuard Home protection is enabled or not.

        Returns
        -------
            The status of the protection of the AdGuard Home instance.

        """
        response = await self.request("status")
        return response["protection_enabled"]

    async def enable_protection(self) -> None:
        """Enable AdGuard Home protection.

        Raises
        ------
            AdGuardHomeError: Failed enabling AdGuard Home protection.

        """
        try:
            await self.request(
                "dns_config",
                method="POST",
                json_data={"protection_enabled": True},
            )
        except AdGuardHomeError as exception:
            msg = "Failed enabling AdGuard Home protection"
            raise AdGuardHomeError(msg) from exception

    async def disable_protection(self) -> None:
        """Disable AdGuard Home protection.

        Raises
        ------
            AdGuardHomeError: Failed disabling the AdGuard Home protection.

        """
        try:
            await self.request(
                "dns_config",
                method="POST",
                json_data={"protection_enabled": False},
            )
        except AdGuardHomeError as exception:
            msg = "Failed disabling AdGuard Home protection"
            raise AdGuardHomeError(msg) from exception

    async def version(self) -> str:
        """Return the current version of the AdGuard Home instance.

        Returns
        -------
            The version number of the connected AdGuard Home instance.

        """
        response = await self.request("status")
        return response["version"]

    async def close(self) -> None:
        """Close open client session."""
        if self._session and self._close_session:
            await self._session.close()

    async def __aenter__(self) -> Self:
        """Async enter.

        Returns
        -------
            The AdGuard Home object.

        """
        return self

    async def __aexit__(self, *_exc_info: object) -> None:
        """Async exit.

        Args:
        ----
            _exc_info: Exec type.

        """
        await self.close()
