"""Asynchronous Python client for the AdGuard Home API."""
from __future__ import annotations

from typing import TYPE_CHECKING

from .exceptions import AdGuardHomeError

if TYPE_CHECKING:
    from . import AdGuardHome


class AdGuardHomeSafeSearch:
    """Controls AdGuard Home safe search enforcing."""

    def __init__(self, adguard: AdGuardHome) -> None:
        """Initialize object.

        Args:
            adguard: The AdGuard Home instance.
        """
        self._adguard = adguard

    async def enabled(self) -> bool:
        """Return if AdGuard Home safe search enforcing is enabled or not.

        Returns:
            The current state of the AdGuard Home safe search.
        """
        response = await self._adguard.request("safesearch/status")
        return response["enabled"]

    async def enable(self) -> None:
        """Enable AdGuard Home safe search enforcing.

        Raises:
            AdGuardHomeError: If enabling the safe search didn't succeed.
        """
        try:
            await self._adguard.request("safesearch/enable", method="POST")
        except AdGuardHomeError as exception:
            raise AdGuardHomeError(
                "Enabling AdGuard Home safe search failed"
            ) from exception

    async def disable(self) -> None:
        """Disable AdGuard Home safe search enforcing.

        Raises:
            AdGuardHomeError: If disabling the safe search didn't succeed.
        """
        try:
            await self._adguard.request("safesearch/disable", method="POST")
        except AdGuardHomeError as exception:
            raise AdGuardHomeError(
                "Disabling AdGuard Home safe search failed"
            ) from exception
