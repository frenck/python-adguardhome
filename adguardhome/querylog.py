# -*- coding: utf-8 -*-
"""Asynchronous Python client for the AdGuard Home API."""

from .exceptions import AdGuardHomeError


class AdGuardHomeQueryLog:
    """Controls AdGuard Home query log."""

    def __init__(self, adguard):
        """Initialize object."""
        self._adguard = adguard

    async def enabled(self) -> bool:
        """Return if AdGuard Home query log is enabled or not."""
        response = await self._adguard._request("status")
        return response["querylog_enabled"]

    async def enable(self) -> bool:
        """Enable AdGuard Home query log."""
        response = await self._adguard._request("querylog_enable", method="POST")
        if response.rstrip() != "OK":
            raise AdGuardHomeError(
                "Enabling AdGuard Home query log failed", {"response": response}
            )
        return True

    async def disable(self) -> bool:
        """Disable AdGuard Home query log."""
        response = await self._adguard._request("querylog_disable", method="POST")
        if response.rstrip() != "OK":
            raise AdGuardHomeError(
                "Disabling AdGuard Home query log failed", {"response": response}
            )
        return True
