# -*- coding: utf-8 -*-
"""Asynchronous Python client for the AdGuard Home API."""

from .exceptions import AdGuardHomeError


class AdGuardHomeSafeBrowsing:
    """Controls AdGuard Home browsing security."""

    def __init__(self, adguard):
        """Initialize object."""
        self._adguard = adguard

    async def enabled(self) -> bool:
        """Return if AdGuard Home browsing security is enabled or not."""
        response = await self._adguard._request("safebrowsing/status")
        return response["enabled"]

    async def enable(self) -> bool:
        """Enable AdGuard Home browsing security."""
        response = await self._adguard._request("safebrowsing/enable", method="POST")
        if response.rstrip() != "OK":
            raise AdGuardHomeError(
                "Enabling AdGuard Home safe browsing failed", {"response": response}
            )
        return True

    async def disable(self) -> bool:
        """Disable AdGuard Home browsing security."""
        response = await self._adguard._request("safebrowsing/disable", method="POST")
        if response.rstrip() != "OK":
            raise AdGuardHomeError(
                "Disabling AdGuard Home safe browsing failed", {"response": response}
            )
        return True
