"""Asynchronous Python client for the AdGuard Home API."""
from __future__ import annotations

from typing import TYPE_CHECKING

from .exceptions import AdGuardHomeError

if TYPE_CHECKING:
    from . import AdGuardHome


class AdGuardHomeParental:
    """Controls AdGuard Home parental control."""

    def __init__(self, adguard: AdGuardHome) -> None:
        """Initialize object.

        Args:
            adguard: The AdGuard Home instance.
        """
        self._adguard = adguard

    async def enabled(self) -> bool:
        """Return if AdGuard Home parental control is enabled or not.

        Returns:
            The current state of the AdGuard Home parental control.
        """
        response = await self._adguard.request("parental/status")
        return response["enabled"]

    async def enable(self) -> None:
        """Enable AdGuard Home parental control.

        Raises:
            AdGuardHomeError: If enabling parental control failed.
        """
        try:
            await self._adguard.request(
                "parental/enable", method="POST", data="sensitivity=TEEN"
            )
        except AdGuardHomeError as exception:
            raise AdGuardHomeError(
                "Enabling AdGuard Home parental control failed"
            ) from exception

    async def disable(self) -> None:
        """Disable AdGuard Home parental control.

        Raises:
            AdGuardHomeError: If disabling parental control failed.
        """
        try:
            await self._adguard.request("parental/disable", method="POST")
        except AdGuardHomeError as exception:
            raise AdGuardHomeError(
                "Disabling AdGuard Home parental control failed"
            ) from exception
