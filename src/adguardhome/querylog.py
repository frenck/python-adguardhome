"""Asynchronous Python client for the AdGuard Home API."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .exceptions import AdGuardHomeError

if TYPE_CHECKING:
    from . import AdGuardHome


@dataclass
class AdGuardHomeQueryLog:
    """Controls AdGuard Home query log."""

    adguard: AdGuardHome

    async def _config(
        self, *, enabled: bool | None = None, interval: int | None = None
    ) -> None:
        """Configure query log on AdGuard Home.

        Args:
        ----
            enabled: Enable/disable AdGuard Home query log.
            interval: Number of day to keep data in the logs.

        """
        if enabled is None:
            enabled = await self.enabled()
        if interval is None:
            interval = await self.interval()
        await self.adguard.request(
            "querylog_config",
            method="POST",
            json_data={"enabled": enabled, "interval": interval},
        )

    async def enabled(self) -> bool:
        """Return if AdGuard Home query log is enabled or not.

        Returns
        -------
            The current state of the AdGuard Home query log.

        """
        response = await self.adguard.request("querylog_info")
        return response["enabled"]

    async def enable(self) -> None:
        """Enable AdGuard Home query log.

        Raises
        ------
            AdGuardHomeError: If enabling the query log didn't succeed.

        """
        try:
            await self._config(enabled=True)
        except AdGuardHomeError as exception:
            msg = "Enabling AdGuard Home query log failed"
            raise AdGuardHomeError(msg) from exception

    async def interval(self, interval: int | None = None) -> int:
        """Return or set the time period to keep query log data.

        Args:
        ----
            interval: Set the time period (in days) to keep query log data.

        Returns:
        -------
            The current set time period to keep query log data.

        """
        if interval:
            await self._config(interval=interval)
            return interval

        response = await self.adguard.request("querylog_info")
        return response["interval"]

    async def disable(self) -> None:
        """Disable AdGuard Home query log.

        Raises
        ------
            AdGuardHomeError: If disabling the query filter log didn't succeed.

        """
        try:
            await self._config(enabled=False)
        except AdGuardHomeError as exception:
            msg = "Disabling AdGuard Home query log failed"
            raise AdGuardHomeError(msg) from exception
