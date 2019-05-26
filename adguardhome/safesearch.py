# -*- coding: utf-8 -*-
"""Asynchronous Python client for the AdGuard Home API."""

from .exceptions import AdGuardHomeError


class AdGuardHomeSafeSearch:
    """Controls AdGuard Home safe search enforcing."""

    def __init__(self, adguard):
        """Initialize object."""
        self._adguard = adguard

    async def enabled(self) -> bool:
        """Return if AdGuard Home safe search enforcing is enabled or not."""
        response = await self._adguard._request("safesearch/status")
        return response["enabled"]

    async def enable(self) -> bool:
        """Enable AdGuard Home safe search enforcing."""
        response = await self._adguard._request("safesearch/enable", method="POST")
        if response.rstrip() != "OK":
            raise AdGuardHomeError(
                "Enabling AdGuard Home safe search failed", {"response": response}
            )
        return True

    async def disable(self) -> bool:
        """Disable AdGuard Home safe search enforcing."""
        response = await self._adguard._request("safesearch/disable", method="POST")
        if response.rstrip() != "OK":
            raise AdGuardHomeError(
                "Disabling AdGuard Home safe search failed", {"response": response}
            )
        return True
