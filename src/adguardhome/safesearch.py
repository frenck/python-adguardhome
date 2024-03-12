"""Asynchronous Python client for the AdGuard Home API."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .exceptions import AdGuardHomeError

if TYPE_CHECKING:
    from . import AdGuardHome


@dataclass
class AdGuardHomeSafeSearch:
    """Controls AdGuard Home safe search enforcing."""

    adguard: AdGuardHome

    async def enabled(self) -> bool:
        """Return if AdGuard Home safe search enforcing is enabled or not.

        Returns
        -------
            The current state of the AdGuard Home safe search.

        """
        response = await self.adguard.request("safesearch/status")
        return response["enabled"]

    async def enable(self) -> None:
        """Enable AdGuard Home safe search enforcing.

        Raises
        ------
            AdGuardHomeError: If enabling the safe search didn't succeed.

        """
        try:
            await self.adguard.request("safesearch/enable", method="POST")
        except AdGuardHomeError as exception:
            msg = "Enabling AdGuard Home safe search failed"
            raise AdGuardHomeError(msg) from exception

    async def disable(self) -> None:
        """Disable AdGuard Home safe search enforcing.

        Raises
        ------
            AdGuardHomeError: If disabling the safe search didn't succeed.

        """
        try:
            await self.adguard.request("safesearch/disable", method="POST")
        except AdGuardHomeError as exception:
            msg = "Disabling AdGuard Home safe search failed"
            raise AdGuardHomeError(msg) from exception
