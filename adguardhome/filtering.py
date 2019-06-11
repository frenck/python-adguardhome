# -*- coding: utf-8 -*-
"""Asynchronous Python client for the AdGuard Home API."""

from .exceptions import AdGuardHomeError


class AdGuardHomeFiltering:
    """Controls AdGuard Home filtering. Blocks domains."""

    def __init__(self, adguard):
        """Initialize object."""
        self._adguard = adguard

    async def enabled(self) -> bool:
        """Return if AdGuard Home filtering is enabled or not."""
        response = await self._adguard._request("filtering/status")
        return response["enabled"]

    async def enable(self) -> bool:
        """Enable AdGuard Home filtering."""
        response = await self._adguard._request("filtering/enable", method="POST")
        if response.rstrip() != "OK":
            raise AdGuardHomeError(
                "Enabling AdGuard Home filtering failed", {"response": response}
            )
        return True

    async def disable(self) -> bool:
        """Disable AdGuard Home filtering."""
        response = await self._adguard._request("filtering/disable", method="POST")
        if response.rstrip() != "OK":
            raise AdGuardHomeError(
                "Disabling AdGuard Home filtering failed", {"response": response}
            )
        return True

    async def rules_count(self) -> int:
        """Return the number of rules loaded."""
        response = await self._adguard._request("filtering/status")
        count = 0
        for filt in response["filters"]:
            count += filt["rulesCount"]
        return count

    async def add_url(self, name: str, url: str) -> bool:
        """Add a new filter subscription to AdGuard Home."""
        response = await self._adguard._request(
            "filtering/add_url", method="POST", json_data={"name": name, "url": url}
        )
        if not response.startswith("OK"):
            raise AdGuardHomeError(
                "Failed adding URL to AdGuard Home filter", {"response": response}
            )
        return True

    async def remove_url(self, url: str) -> bool:
        """Remove a new filter subscription from AdGuard Home."""
        response = await self._adguard._request(
            "filtering/remove_url", method="POST", json_data={"url": url}
        )
        if response.rstrip() != "OK":
            raise AdGuardHomeError(
                "Failed removing URL from AdGuard Home filter", {"response": response}
            )
        return True

    async def enable_url(self, url: str) -> bool:
        """Enable a filter subscription in AdGuard Home."""
        response = await self._adguard._request(
            "filtering/enable_url", method="POST", data="url={}".format(url)
        )
        if response.rstrip() != "OK":
            raise AdGuardHomeError(
                "Failed enabling URL on AdGuard Home filter", {"response": response}
            )
        return True

    async def disable_url(self, url: str) -> bool:
        """Disable a filter subscription in AdGuard Home."""
        response = await self._adguard._request(
            "filtering/disable_url", method="POST", data="url={}".format(url)
        )
        if response.rstrip() != "OK":
            raise AdGuardHomeError(
                "Failed disabling URL on AdGuard Home filter", {"response": response}
            )
        return True

    async def refresh(self, force=False) -> bool:
        """Reload filtering subscriptions from URLs specified in AdGuard Home."""
        force = "true" if force else "false"
        response = await self._adguard._request(
            "filtering/refresh", method="POST", params={"force": force}
        )
        if not response.startswith("OK"):
            raise AdGuardHomeError(
                "Failed refreshing filter URLs in AdGuard Home", {"response": response}
            )
        return True
