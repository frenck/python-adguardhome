"""Features of AdGuard Home that only turn on and off."""

from __future__ import annotations

from dataclasses import dataclass

from ._area import Area, Requester
from ._model import AdGuardHomeModel


@dataclass(frozen=True, kw_only=True)
class ToggleStatus(AdGuardHomeModel):
    """Status of a feature that only turns on and off."""

    enabled: bool


class Toggle(Area):
    """A feature of AdGuard Home that only turns on and off.

    Parental control and safe browsing have no settings besides being
    enabled, and share the same API under their own path.
    """

    __slots__ = ("_path",)

    def __init__(self, request: Requester, path: str) -> None:
        """Initialize the feature.

        Args:
        ----
            request: The request method of the AdGuard Home client.
            path: The API path of the feature, like `parental`.

        """
        super().__init__(request)
        self._path = path

    async def enabled(self) -> bool:
        """Return if the feature is enabled.

        Returns
        -------
            True if the feature is enabled, False otherwise.

        """
        response = await self._request(f"{self._path}/status")
        return ToggleStatus.from_api(response).enabled

    async def enable(self) -> None:
        """Enable the feature."""
        await self._request(f"{self._path}/enable", method="POST")

    async def disable(self) -> None:
        """Disable the feature."""
        await self._request(f"{self._path}/disable", method="POST")
