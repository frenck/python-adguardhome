"""Asynchronous Python client for the AdGuard Home API."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .exceptions import AdGuardHomeError

if TYPE_CHECKING:
    from . import AdGuardHome


@dataclass
class AdGuardHomeAvailableUpdate:
    """Latests available AdGuard Home update."""

    new_version: str
    announcement: str
    announcement_url: str
    can_autoupdate: bool
    disabled: bool


@dataclass
class AdGuardHomeUpdate:
    """Controls AdGuard Home version update."""

    adguard: AdGuardHome

    async def update_available(self) -> AdGuardHomeAvailableUpdate:
        """Return AdGuard Home latest available update.

        Returns
        -------
            An AdGuardHomeAvailableUpdate object with all data about the latest update.

        """
        response = await self.adguard.request("version.json", method="POST")
        return AdGuardHomeAvailableUpdate(**response)

    async def begin_update(self) -> None:
        """Begin AdGuard Home auto-upgrade procedure.

        Raises
        ------
            AdGuardHomeError: If beginning the auto-upgrade failed.

        """
        try:
            await self.adguard.request("update", method="POST")
        except AdGuardHomeError as exception:
            msg = "Begin AdGuard Home update failed"
            raise AdGuardHomeError(msg) from exception
