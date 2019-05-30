# -*- coding: utf-8 -*-
"""Asynchronous Python client for the AdGuard Home API."""
import asyncio
import json
import socket

import aiohttp
import async_timeout
from yarl import URL

from .__version__ import __version__
from .exceptions import AdGuardHomeConnectionError, AdGuardHomeError
from .filtering import AdGuardHomeFiltering
from .parental import AdGuardHomeParental
from .querylog import AdGuardHomeQueryLog
from .safebrowsing import AdGuardHomeSafeBrowsing
from .safesearch import AdGuardHomeSafeSearch
from .stats import AdGuardHomeStats


class AdGuardHome:
    """Main class for handling connections with AdGuard Home."""

    def __init__(
        self,
        host: str,
        base_path: str = "/control",
        loop=None,
        password: str = None,
        port: int = 3000,
        request_timeout: int = 10,
        session=None,
        tls: bool = False,
        username: str = None,
        verify_ssl: bool = True,
        user_agent: str = None,
    ):
        """Initialize connection with AdGuard Home."""
        self._loop = loop
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
        self.user_agent = user_agent

        if self._loop is None:
            self._loop = asyncio.get_event_loop()

        if self._session is None:
            self._session = aiohttp.ClientSession(loop=self._loop)
            self._close_session = True

        if self.user_agent is None:
            self.user_agent = "PythonAdGuardHome/{}".format(__version__)

        if self.base_path[-1] != "/":
            self.base_path = self.base_path + "/"

        self.filtering = AdGuardHomeFiltering(self)
        self.parental = AdGuardHomeParental(self)
        self.querylog = AdGuardHomeQueryLog(self)
        self.safebrowsing = AdGuardHomeSafeBrowsing(self)
        self.safesearch = AdGuardHomeSafeSearch(self)
        self.stats = AdGuardHomeStats(self)

    async def _request(
        self, uri: str, method: str = "GET", data=None, json_data=None, params=None
    ):
        """Handle a request to the AdGuard Home instance."""
        scheme = "https" if self.tls else "http"
        url = URL.build(
            scheme=scheme, host=self.host, port=self.port, path=self.base_path
        ).join(URL(uri))

        auth = None
        if self.username and self.password:
            auth = aiohttp.BasicAuth(self.username, self.password)

        headers = {
            "User-Agent": self.user_agent,
            "Accept": "application/json, text/plain, */*",
        }

        try:
            with async_timeout.timeout(self.request_timeout):
                response = await self._session.request(
                    method,
                    url,
                    auth=auth,
                    data=data,
                    json=json_data,
                    params=params,
                    headers=headers,
                    ssl=self.verify_ssl,
                )
        except asyncio.TimeoutError as exception:
            raise AdGuardHomeConnectionError(
                "Timeout occurred while connecting to AdGuard Home instance."
            ) from exception
        except (aiohttp.ClientError, socket.gaierror) as exception:
            raise AdGuardHomeConnectionError(
                "Error occurred while communicating with AdGuard Home."
            ) from exception

        content_type = response.headers.get("Content-Type", "")
        if (response.status // 100) in [4, 5]:
            contents = await response.read()
            response.close()

            if content_type == "application/json":
                raise AdGuardHomeError(
                    response.status, json.loads(contents.decode("utf8"))
                )
            raise AdGuardHomeError(
                response.status, {"message": contents.decode("utf8")}
            )

        if "application/json" in response.headers["Content-Type"]:
            return await response.json()
        return await response.text()

    async def protection_enabled(self) -> bool:
        """Return if AdGuard Home protection is enabled or not."""
        response = await self._request("status")
        return response["protection_enabled"]

    async def enable_protection(self) -> bool:
        """Enable AdGuard Home protection."""
        response = await self._request("enable_protection", method="POST")
        if response.rstrip() != "OK":
            raise AdGuardHomeError(
                "Enabling AdGuard Home protection failed", {"response": response}
            )
        return True

    async def disable_protection(self) -> bool:
        """Disable AdGuard Home protection."""
        response = await self._request("disable_protection", method="POST")
        if response.rstrip() != "OK":
            raise AdGuardHomeError(
                "Disabling AdGuard Home protection failed", {"response": response}
            )
        return True

    async def version(self) -> str:
        """Return the current version of the AdGuard Home instance."""
        response = await self._request("status")
        return response["version"]

    async def close(self) -> None:
        """Close open client session."""
        if self._close_session:
            await self._session.close()

    async def __aenter__(self) -> "AdGuardHome":
        """Async enter."""
        return self

    async def __aexit__(self, *exc_info) -> None:
        """Async exit."""
        await self.close()
