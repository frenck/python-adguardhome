"""Blocked services of AdGuard Home, like social networks or games."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import timedelta

from mashumaro import field_options

from ._area import Area
from ._model import AdGuardHomeModel, MillisecondsStrategy


@dataclass(frozen=True, kw_only=True)
class DayRange(AdGuardHomeModel):
    """A time range within a day, as time since midnight.

    The range includes `start`, but stops just before `end`. An `end` of
    24 hours runs until the end of the day.
    """

    start: timedelta = field(
        metadata=field_options(serialization_strategy=MillisecondsStrategy())
    )
    end: timedelta = field(
        metadata=field_options(serialization_strategy=MillisecondsStrategy())
    )


@dataclass(frozen=True, kw_only=True)
class Schedule(AdGuardHomeModel):
    """Weekly schedule of when blocked services are not blocked.

    A day without a range has no pause at all.
    """

    # An IANA time zone, like `Europe/Amsterdam`, or `Local` for the time
    # zone of the AdGuard Home server.
    time_zone: str = "Local"

    sun: DayRange | None = None
    mon: DayRange | None = None
    tue: DayRange | None = None
    wed: DayRange | None = None
    thu: DayRange | None = None
    fri: DayRange | None = None
    sat: DayRange | None = None


@dataclass(frozen=True, kw_only=True)
class Service(AdGuardHomeModel):
    """A service AdGuard Home knows how to block."""

    id: str
    name: str
    icon_svg: str
    group_id: str
    rules: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True)
class ServiceGroup(AdGuardHomeModel):
    """A group of services, like social networks, to block at once."""

    id: str


@dataclass(frozen=True, kw_only=True)
class AvailableServices(AdGuardHomeModel):
    """All services AdGuard Home knows how to block."""

    services: tuple[Service, ...] = field(
        default=(), metadata=field_options(alias="blocked_services")
    )
    groups: tuple[ServiceGroup, ...] = ()


@dataclass(frozen=True, kw_only=True)
class BlockedServicesConfig(AdGuardHomeModel):
    """Which services AdGuard Home blocks, and when it pauses blocking them."""

    # The IDs of the blocked services, like `youtube`.
    blocked: tuple[str, ...] = field(default=(), metadata=field_options(alias="ids"))

    # When the blocking pauses. None means it never pauses.
    schedule: Schedule | None = None


class AdGuardHomeBlockedServices(Area):
    """Blocked services of AdGuard Home, like social networks or games."""

    __slots__ = ()

    async def get(self) -> AvailableServices:
        """Return all services AdGuard Home knows how to block.

        Returns
        -------
            The services, with their names and icons, and their groups.

        """
        return AvailableServices.from_api(await self._request("blocked_services/all"))

    async def config(self) -> BlockedServicesConfig:
        """Return which services are blocked, and when blocking pauses.

        Returns
        -------
            The blocked services and their schedule.

        """
        return BlockedServicesConfig.from_api(
            await self._request("blocked_services/get")
        )

    async def set_config(self, config: BlockedServicesConfig) -> None:
        """Replace which services are blocked, and when blocking pauses.

        Args:
        ----
            config: The new blocked services and their schedule.

        """
        await self._request(
            "blocked_services/update", method="PUT", json=config.to_dict()
        )

    async def block(self, *ids: str) -> None:
        """Start blocking services, keeping the ones already blocked.

        Args:
        ----
            ids: The IDs of the services to block, like `youtube`.

        """
        config = await self.config()
        new = tuple(service for service in ids if service not in config.blocked)
        blocked = (*config.blocked, *new)
        await self.set_config(replace(config, blocked=blocked))

    async def unblock(self, *ids: str) -> None:
        """Stop blocking services, keeping the other ones blocked.

        Args:
        ----
            ids: The IDs of the services to stop blocking.

        """
        config = await self.config()
        blocked = tuple(service for service in config.blocked if service not in ids)
        await self.set_config(replace(config, blocked=blocked))
