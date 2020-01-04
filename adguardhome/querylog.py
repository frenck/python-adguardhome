"""Asynchronous Python client for the AdGuard Home API."""

from typing import Optional

from .exceptions import AdGuardHomeError


class AdGuardHomeQueryLog:
    """Controls AdGuard Home query log."""

    def __init__(self, adguard) -> None:
        """Initialize object."""
        self._adguard = adguard

    async def _config(
        self, enabled: Optional[bool] = None, interval: Optional[int] = None
    ):
        """Configure query log on AdGuard Home."""
        if enabled is None:
            enabled = await self.enabled()
        if interval is None:
            interval = await self.interval()
        await self._adguard._request(
            "querylog_config",
            method="POST",
            json_data={"enabled": enabled, "interval": interval},
        )

    async def enabled(self) -> bool:
        """Return if AdGuard Home query log is enabled or not."""
        response = await self._adguard._request("querylog_info")
        return response["enabled"]

    async def enable(self) -> None:
        """Enable AdGuard Home query log."""
        try:
            await self._config(enabled=True)
        except AdGuardHomeError as exception:
            raise AdGuardHomeError("Enabling AdGuard Home query log failed", exception)

    async def interval(self, interval: Optional[int] = None) -> int:
        """Return or set the time period to keep query log data."""
        if interval:
            await self._config(interval=interval)
            return interval

        response = await self._adguard._request("querylog_info")
        return response["interval"]

    async def disable(self) -> None:
        """Disable AdGuard Home query log."""
        try:
            await self._config(enabled=False)
        except AdGuardHomeError as exception:
            raise AdGuardHomeError("Disabling AdGuard Home query log failed", exception)
