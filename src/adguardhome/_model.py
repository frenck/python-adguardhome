"""Shared building blocks for the AdGuard Home models."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Self

from awesomeversion import AwesomeVersion
from mashumaro.config import BaseConfig
from mashumaro.mixins.orjson import DataClassORJSONMixin
from mashumaro.types import SerializationStrategy

from .exceptions import AdGuardHomeError

MILLISECOND = timedelta(milliseconds=1)


class VersionStrategy(SerializationStrategy):
    """Convert a version string to an AwesomeVersion."""

    def serialize(self, value: AwesomeVersion) -> str:
        """Serialize to a version string."""
        return str(value)

    def deserialize(self, value: str) -> AwesomeVersion:
        """Deserialize from a version string."""
        return AwesomeVersion(value)


class MillisecondsStrategy(SerializationStrategy):
    """Convert a duration in milliseconds to a timedelta."""

    def serialize(self, value: timedelta) -> int:
        """Serialize to milliseconds."""
        return value // MILLISECOND

    def deserialize(self, value: float) -> timedelta:
        """Deserialize from milliseconds."""
        return timedelta(milliseconds=value)


class HoursStrategy(SerializationStrategy):
    """Convert a duration in whole hours to a timedelta."""

    def serialize(self, value: timedelta) -> int:
        """Serialize to whole hours."""
        return value // timedelta(hours=1)

    def deserialize(self, value: int) -> timedelta:
        """Deserialize from hours."""
        return timedelta(hours=value)


class SecondsStrategy(SerializationStrategy):
    """Convert a duration in (fractional) seconds to a timedelta."""

    def serialize(self, value: timedelta) -> float:
        """Serialize to seconds."""
        return value.total_seconds()

    def deserialize(self, value: float) -> timedelta:
        """Deserialize from seconds."""
        return timedelta(seconds=value)


class OptionalMillisecondsStrategy(SerializationStrategy):
    """Convert a duration in milliseconds to a timedelta, with 0 as None.

    AdGuard Home reports a duration that is not running (like a protection
    pause when protection is active) as 0, which means "nothing" rather
    than "zero time left".
    """

    def serialize(self, value: timedelta) -> int:
        """Serialize to milliseconds.

        Mashumaro handles None itself and never passes it to a strategy,
        so a None is left out instead of serialized to 0.
        """
        return value // MILLISECOND

    def deserialize(self, value: float) -> timedelta | None:
        """Deserialize from milliseconds, 0 becomes None."""
        return timedelta(milliseconds=value) if value else None


class UnixMillisecondsStrategy(SerializationStrategy):
    """Convert a Unix timestamp in milliseconds to a UTC datetime."""

    def serialize(self, value: datetime) -> float:
        """Serialize to a Unix timestamp in milliseconds."""
        return value.timestamp() * 1000

    def deserialize(self, value: float) -> datetime:
        """Deserialize from a Unix timestamp in milliseconds."""
        return datetime.fromtimestamp(value / 1000, tz=UTC)


class AdGuardHomeModel(DataClassORJSONMixin):
    """Base class for all AdGuard Home models."""

    # pylint: disable-next=too-few-public-methods
    class Config(BaseConfig):
        """Mashumaro configuration."""

        # Settings are sent back to AdGuard Home, so serialize to the
        # names the API uses, not the names of our fields. Leave out what we
        # do not have, instead of sending AdGuard Home a null it may reject.
        serialize_by_alias = True
        omit_none = True
        serialization_strategy = {  # noqa: RUF012
            AwesomeVersion: VersionStrategy(),
        }

    @classmethod
    def __pre_deserialize__(cls, d: dict[Any, Any]) -> dict[Any, Any]:
        """Drop null values, so the defaults of the fields apply.

        AdGuard Home is written in Go, which encodes an empty list as null.
        Treating null as "not there" lets an empty list default to empty.
        """
        return {key: value for key, value in d.items() if value is not None}

    @classmethod
    def from_api(cls, data: Any) -> Self:
        """Create the model from an AdGuard Home API response.

        Mashumaro raises its own exceptions on data it cannot handle. This
        turns those into an AdGuardHomeError, so a consumer only ever has to
        deal with the exceptions of this library.

        Args:
        ----
            data: The decoded JSON response from the API.

        Returns:
        -------
            The model, populated with the response data.

        Raises:
        ------
            AdGuardHomeError: The response did not match the model.

        """
        try:
            return cls.from_dict(data)
        except (AttributeError, LookupError, TypeError, ValueError) as exception:
            msg = f"Unexpected {cls.__name__} data from AdGuard Home"
            raise AdGuardHomeError(msg) from exception
