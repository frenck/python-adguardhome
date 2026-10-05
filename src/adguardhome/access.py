"""Access lists of AdGuard Home: which clients may use it, and which hosts."""

from __future__ import annotations

from dataclasses import dataclass

from ._area import Area
from ._model import AdGuardHomeModel


@dataclass(frozen=True, kw_only=True)
class AccessConfig(AdGuardHomeModel):
    """Which clients may use AdGuard Home, and which hosts it refuses.

    Clients are IP addresses, CIDR ranges, or ClientIDs. When there are
    allowed clients, AdGuard Home refuses every other client, and ignores
    the disallowed ones.
    """

    allowed_clients: tuple[str, ...] = ()
    disallowed_clients: tuple[str, ...] = ()

    # Hosts AdGuard Home drops queries for, written as filtering rules.
    blocked_hosts: tuple[str, ...] = ()


class AdGuardHomeAccess(Area):
    """Access lists of AdGuard Home: which clients may use it, and which hosts."""

    __slots__ = ()

    async def config(self) -> AccessConfig:
        """Return the access lists.

        Returns
        -------
            The allowed and disallowed clients, and the blocked hosts.

        """
        return AccessConfig.from_api(await self._request("access/list"))

    async def set_config(self, config: AccessConfig) -> None:
        """Replace the access lists.

        Args:
        ----
            config: The new access lists.

        """
        await self._request("access/set", method="POST", json=config.to_dict())
