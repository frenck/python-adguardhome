"""Asynchronous Python client for the AdGuard Home API."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .exceptions import AdGuardHomeError

if TYPE_CHECKING:
    from . import AdGuardHome


@dataclass
class AdGuardHomeSafeBrowsing:
    """Controls AdGuard Home browsing security."""

    adguard: AdGuardHome

    async def enabled(self) -> bool:
        """Return if AdGuard Home browsing security is enabled or not.

        Returns
        -------
            The current state of the AdGuard safe browsing feature.

        """
        response = await self.adguard.request("safebrowsing/status")
        return response["enabled"]

    async def enable(self) -> None:
        """Enable AdGuard Home browsing security.

        Raises
        ------
            AdGuardHomeError: If enabling the safe browsing didn't succeed.

        """
        try:
            await self.adguard.request("safebrowsing/enable", method="POST")
        except AdGuardHomeError as exception:
            msg = "Enabling AdGuard Home safe browsing failed"
            raise AdGuardHomeError(msg) from exception

    async def disable(self) -> None:
        """Disable AdGuard Home browsing security.

        Raises
        ------
            AdGuardHomeError: If disabling the safe browsing didn't succeed.

        """
        try:
            await self.adguard.request("safebrowsing/disable", method="POST")
        except AdGuardHomeError as exception:
            msg = "Disabling AdGuard Home safe browsing failed"
            raise AdGuardHomeError(msg) from exception
