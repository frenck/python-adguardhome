"""Asynchronous Python client for the AdGuard Home API."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .exceptions import AdGuardHomeError

if TYPE_CHECKING:
    from . import AdGuardHome


@dataclass
class AdGuardHomeParental:
    """Controls AdGuard Home parental control."""

    adguard: AdGuardHome

    async def enabled(self) -> bool:
        """Return if AdGuard Home parental control is enabled or not.

        Returns
        -------
            The current state of the AdGuard Home parental control.

        """
        response = await self.adguard.request("parental/status")
        return response["enabled"]

    async def enable(self) -> None:
        """Enable AdGuard Home parental control.

        Raises
        ------
            AdGuardHomeError: If enabling parental control failed.

        """
        try:
            await self.adguard.request("parental/enable", method="POST")
        except AdGuardHomeError as exception:
            msg = "Enabling AdGuard Home parental control failed"
            raise AdGuardHomeError(msg) from exception

    async def disable(self) -> None:
        """Disable AdGuard Home parental control.

        Raises
        ------
            AdGuardHomeError: If disabling parental control failed.

        """
        try:
            await self.adguard.request("parental/disable", method="POST")
        except AdGuardHomeError as exception:
            msg = "Disabling AdGuard Home parental control failed"
            raise AdGuardHomeError(msg) from exception
