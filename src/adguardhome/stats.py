"""Statistics of AdGuard Home."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import timedelta
from enum import StrEnum

from mashumaro import field_options
from mashumaro.types import SerializationStrategy

from ._area import Area
from ._model import AdGuardHomeModel, MillisecondsStrategy, SecondsStrategy


class TimeUnit(StrEnum):
    """Time unit of each entry in the statistics history."""

    HOURS = "hours"
    DAYS = "days"


class TopCountsStrategy(SerializationStrategy):
    """Convert a top list of AdGuard Home to an ordered dictionary.

    AdGuard Home sends a top list as a list of single-key objects, like
    `[{"example.com": 42}, {"example.org": 21}]`. A dictionary keeps the
    order, so the first key is still the top entry.
    """

    def serialize(self, value: dict[str, int]) -> list[dict[str, int]]:
        """Serialize to a list of single-key objects."""
        return [{key: count} for key, count in value.items()]

    def deserialize(self, value: list[dict[str, int]]) -> dict[str, int]:
        """Deserialize from a list of single-key objects."""
        return {key: _count(count) for entry in value for key, count in entry.items()}


class TopDurationsStrategy(SerializationStrategy):
    """Convert a top list of durations in seconds to an ordered dictionary."""

    def serialize(self, value: dict[str, timedelta]) -> list[dict[str, float]]:
        """Serialize to a list of single-key objects in seconds."""
        return [{key: duration.total_seconds()} for key, duration in value.items()]

    def deserialize(self, value: list[dict[str, float]]) -> dict[str, timedelta]:
        """Deserialize from a list of single-key objects in seconds."""
        return {
            key: timedelta(seconds=_seconds(seconds))
            for entry in value
            for key, seconds in entry.items()
        }


def _count(value: object) -> int:
    """Return a count from a top list, rejecting anything that is not one.

    Mashumaro does not check what a strategy returns, and Python would happily
    turn a string, a fraction, or a boolean into a count.

    Raises
    ------
        TypeError: The value is not a whole number.

    """
    if isinstance(value, bool) or not isinstance(value, int):
        msg = f"Expected a count, got {value!r}"
        raise TypeError(msg)
    return value


def _seconds(value: object) -> float:
    """Return a duration in seconds from a top list, rejecting anything else.

    Raises
    ------
        TypeError: The value is not a number.

    """
    if isinstance(value, bool) or not isinstance(value, int | float):
        msg = f"Expected a number of seconds, got {value!r}"
        raise TypeError(msg)
    return float(value)


def _top_counts(alias: str) -> dict[str, object]:
    """Return the metadata of a field holding a top list of counts."""
    return field_options(alias=alias, serialization_strategy=TopCountsStrategy())


@dataclass(frozen=True, kw_only=True)
class Stats(AdGuardHomeModel):
    """Statistics of AdGuard Home, over the configured retention period.

    The top lists are ordered dictionaries: the first entry is the top one.
    The history lists hold one value per time unit, oldest first.
    """

    dns_queries: int = field(metadata=field_options(alias="num_dns_queries"))
    blocked_filtering: int = field(
        metadata=field_options(alias="num_blocked_filtering")
    )
    blocked_safebrowsing: int = field(
        metadata=field_options(alias="num_replaced_safebrowsing")
    )
    blocked_parental: int = field(metadata=field_options(alias="num_replaced_parental"))
    enforced_safesearch: int = field(
        metadata=field_options(alias="num_replaced_safesearch")
    )
    avg_processing_time: timedelta = field(
        metadata=field_options(serialization_strategy=SecondsStrategy())
    )

    top_queried_domains: dict[str, int] = field(
        default_factory=dict, metadata=_top_counts("top_queried_domains")
    )
    top_blocked_domains: dict[str, int] = field(
        default_factory=dict, metadata=_top_counts("top_blocked_domains")
    )
    top_clients: dict[str, int] = field(
        default_factory=dict, metadata=_top_counts("top_clients")
    )
    top_upstream_responses: dict[str, int] = field(
        default_factory=dict, metadata=_top_counts("top_upstreams_responses")
    )
    top_upstream_avg_time: dict[str, timedelta] = field(
        default_factory=dict,
        metadata=field_options(
            alias="top_upstreams_avg_time",
            serialization_strategy=TopDurationsStrategy(),
        ),
    )

    time_unit: TimeUnit = field(metadata=field_options(alias="time_units"))
    dns_queries_history: tuple[int, ...] = field(
        default=(), metadata=field_options(alias="dns_queries")
    )
    blocked_filtering_history: tuple[int, ...] = field(
        default=(), metadata=field_options(alias="blocked_filtering")
    )
    blocked_safebrowsing_history: tuple[int, ...] = field(
        default=(), metadata=field_options(alias="replaced_safebrowsing")
    )
    blocked_parental_history: tuple[int, ...] = field(
        default=(), metadata=field_options(alias="replaced_parental")
    )

    @property
    def blocked_percentage(self) -> float:
        """Return the percentage of DNS queries blocked by filtering."""
        if not self.dns_queries:
            return 0.0

        return self.blocked_filtering / self.dns_queries * 100


@dataclass(frozen=True, kw_only=True)
class StatsConfig(AdGuardHomeModel):
    """Configuration of the AdGuard Home statistics."""

    enabled: bool
    retention: timedelta = field(
        metadata=field_options(
            alias="interval", serialization_strategy=MillisecondsStrategy()
        )
    )
    ignored: tuple[str, ...] = ()

    # Added in AdGuard Home v0.107.72. Older versions leave it out, and
    # AdGuard Home treats it as enabled when the ignored list is not empty.
    ignored_enabled: bool | None = None


class AdGuardHomeStats(Area):
    """Statistics of AdGuard Home."""

    __slots__ = ()

    async def get(self) -> Stats:
        """Return the statistics over the configured retention period.

        Returns
        -------
            The totals, top lists, and history of the statistics.

        """
        return Stats.from_api(await self._request("stats"))

    async def config(self) -> StatsConfig:
        """Return the configuration of the statistics.

        Returns
        -------
            The current configuration of the statistics.

        """
        return StatsConfig.from_api(await self._request("stats/config"))

    async def set_config(self, config: StatsConfig) -> None:
        """Replace the configuration of the statistics.

        Use `dataclasses.replace` on the result of `config()` to change
        only part of it.

        Args:
        ----
            config: The new configuration of the statistics.

        """
        await self._request("stats/config/update", method="PUT", json=config.to_dict())

    async def enable(self) -> None:
        """Enable the statistics."""
        await self.set_config(replace(await self.config(), enabled=True))

    async def disable(self) -> None:
        """Disable the statistics."""
        await self.set_config(replace(await self.config(), enabled=False))

    async def reset(self) -> None:
        """Reset all statistics."""
        await self._request("stats_reset", method="POST")
