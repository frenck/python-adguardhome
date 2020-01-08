"""Asynchronous Python client for the AdGuard Home API."""
import asyncio
import json
import socket
from typing import Any, Mapping, Optional

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
        password: str = None,
        port: int = 3000,
        request_timeout: int = 10,
        session: aiohttp.client.ClientSession = None,
        tls: bool = False,
        username: str = None,
        verify_ssl: bool = True,
        user_agent: str = None,
    ) -> None:
        """Initialize connection with AdGuard Home."""
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

        if user_agent is None:
            self.user_agent = "PythonAdGuardHome/{}".format(__version__)

        if self.base_path[-1] != "/":
            self.base_path += "/"

        self.filtering = AdGuardHomeFiltering(self)
        self.parental = AdGuardHomeParental(self)
        self.querylog = AdGuardHomeQueryLog(self)
        self.safebrowsing = AdGuardHomeSafeBrowsing(self)
        self.safesearch = AdGuardHomeSafeSearch(self)
        self.stats = AdGuardHomeStats(self)

    async def _request(
        self,
        uri: str,
        method: str = "GET",
        data: Optional[Any] = None,
        json_data: Optional[dict] = None,
        params: Optional[Mapping[str, str]] = None,
    ) -> Any:
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

        if self._session is None:
            self._session = aiohttp.ClientSession()
            self._close_session = True

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

        if "application/json" in content_type:
            return await response.json()

        # Workaround for incorrect content-type headers for the stats call
        # https://github.com/AdguardTeam/AdGuardHome/issues/1086
        text = await response.text()
        if uri == "stats":
            return json.loads(text)

        return text

    async def protection_enabled(self) -> bool:
        """Return if AdGuard Home protection is enabled or not."""
        response = await self._request("status")
        return response["protection_enabled"]

    async def enable_protection(self) -> None:
        """Enable AdGuard Home protection."""
        await self._request(
            "dns_config", method="POST", json_data={"protection_enabled": True},
        )

    async def disable_protection(self) -> None:
        """Disable AdGuard Home protection."""
        await self._request(
            "dns_config", method="POST", json_data={"protection_enabled": False},
        )

    async def version(self) -> str:
        """Return the current version of the AdGuard Home instance."""
        response = await self._request("status")
        return response["version"]

    async def close(self) -> None:
        """Close open client session."""
        if self._session and self._close_session:
            await self._session.close()

    async def __aenter__(self) -> "AdGuardHome":
        """Async enter."""
        return self

    async def __aexit__(self, *exc_info) -> None:
        """Async exit."""
        await self.close()
