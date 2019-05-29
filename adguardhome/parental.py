# -*- coding: utf-8 -*-
"""Asynchronous Python client for the AdGuard Home API."""

from .exceptions import AdGuardHomeError


class AdGuardHomeParental:
    """Controls AdGuard Home parental control."""

    def __init__(self, adguard):
        """Initialize object."""
        self._adguard = adguard

    async def enabled(self) -> bool:
        """Return if AdGuard Home parental control is enabled or not ."""
        response = await self._adguard._request("parental/status")
        return response["enabled"]

    async def enable(self) -> bool:
        """Enable AdGuard Home parental control."""
        response = await self._adguard._request(
            "parental/enable", method="POST", data="sensitivity=TEEN"
        )
        if response.rstrip() != "OK":
            raise AdGuardHomeError(
                "Enabling AdGuard Home parental control failed", {"response": response}
            )
        return True

    async def disable(self) -> bool:
        """Disable AdGuard Home parental control."""
        response = await self._adguard._request("parental/disable", method="POST")
        if response.rstrip() != "OK":
            raise AdGuardHomeError(
                "Disabling AdGuard Home parental control failed", {"response": response}
            )
        return True
