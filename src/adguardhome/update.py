"""Updates of AdGuard Home itself."""

from __future__ import annotations

from dataclasses import dataclass

from awesomeversion import AwesomeVersion

from ._area import Area
from ._model import AdGuardHomeModel


@dataclass(frozen=True, kw_only=True)
class AvailableUpdate(AdGuardHomeModel):
    """The latest version of AdGuard Home that is available.

    When `disabled` is true, AdGuard Home does not check for updates, and
    all other fields are empty.
    """

    disabled: bool
    new_version: AwesomeVersion | None = None
    announcement: str | None = None
    announcement_url: str | None = None
    can_autoupdate: bool = False


class AdGuardHomeUpdate(Area):
    """Updates of AdGuard Home itself."""

    __slots__ = ()

    async def get(self, *, recheck: bool = False) -> AvailableUpdate:
        """Return the latest version of AdGuard Home that is available.

        Args:
        ----
            recheck: Check for a new version right now. Otherwise, AdGuard
                Home answers from what it checked in the last few hours.

        Returns:
        -------
            The latest available version, and whether it can update itself.

        """
        response = await self._request(
            "version.json", method="POST", json={"recheck_now": recheck}
        )
        return AvailableUpdate.from_api(response)

    async def install(self) -> None:
        """Update AdGuard Home to the latest version.

        AdGuard Home restarts itself to finish the update, so expect it to
        be unreachable for a moment afterwards.
        """
        await self._request("update", method="POST")
