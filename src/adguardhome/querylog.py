"""Query log of AdGuard Home."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import timedelta

from mashumaro import field_options

from ._area import Area
from ._model import AdGuardHomeModel, MillisecondsStrategy


@dataclass(frozen=True, kw_only=True)
class QueryLogConfig(AdGuardHomeModel):
    """Configuration of the AdGuard Home query log."""

    enabled: bool
    retention: timedelta = field(
        metadata=field_options(
            alias="interval", serialization_strategy=MillisecondsStrategy()
        )
    )
    anonymize_client_ip: bool
    ignored: tuple[str, ...] = ()

    # Added in AdGuard Home v0.107.72. Older versions leave it out, and
    # AdGuard Home treats it as enabled when the ignored list is not empty.
    ignored_enabled: bool | None = None


class AdGuardHomeQueryLog(Area):
    """Query log of AdGuard Home."""

    __slots__ = ()

    async def config(self) -> QueryLogConfig:
        """Return the configuration of the query log.

        Returns
        -------
            The current configuration of the query log.

        """
        return QueryLogConfig.from_api(await self._request("querylog/config"))

    async def set_config(self, config: QueryLogConfig) -> None:
        """Replace the configuration of the query log.

        Use `dataclasses.replace` on the result of `config()` to change
        only part of it.

        Args:
        ----
            config: The new configuration of the query log.

        """
        await self._request(
            "querylog/config/update", method="PUT", json=config.to_dict()
        )

    async def enable(self) -> None:
        """Enable the query log."""
        await self.set_config(replace(await self.config(), enabled=True))

    async def disable(self) -> None:
        """Disable the query log."""
        await self.set_config(replace(await self.config(), enabled=False))

    async def clear(self) -> None:
        """Remove all entries from the query log."""
        await self._request("querylog_clear", method="POST")
