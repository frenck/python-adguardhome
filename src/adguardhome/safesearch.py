"""Safe search enforcement of AdGuard Home."""

from __future__ import annotations

from dataclasses import dataclass, replace

from ._area import Area
from ._model import AdGuardHomeModel


@dataclass(frozen=True, kw_only=True)
class SafeSearchConfig(AdGuardHomeModel):
    """Configuration of safe search, overall and per service."""

    enabled: bool
    bing: bool = False
    duckduckgo: bool = False
    ecosia: bool = False
    google: bool = False
    pixabay: bool = False
    yandex: bool = False
    youtube: bool = False


class AdGuardHomeSafeSearch(Area):
    """Safe search enforcement of AdGuard Home."""

    __slots__ = ()

    async def config(self) -> SafeSearchConfig:
        """Return the configuration of safe search.

        Returns
        -------
            Whether safe search is enabled, overall and per service.

        """
        return SafeSearchConfig.from_api(await self._request("safesearch/status"))

    async def set_config(self, config: SafeSearchConfig) -> None:
        """Replace the configuration of safe search.

        Args:
        ----
            config: The new configuration of safe search.

        """
        await self._request("safesearch/settings", method="PUT", json=config.to_dict())

    async def enable(self) -> None:
        """Enable safe search, for the services it is configured for."""
        await self.set_config(replace(await self.config(), enabled=True))

    async def disable(self) -> None:
        """Disable safe search."""
        await self.set_config(replace(await self.config(), enabled=False))
