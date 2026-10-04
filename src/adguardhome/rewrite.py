"""DNS rewrites of AdGuard Home."""

from __future__ import annotations

from dataclasses import dataclass

from ._area import Area
from ._model import AdGuardHomeModel


@dataclass(frozen=True, kw_only=True)
class RewriteRule(AdGuardHomeModel):
    """A DNS rewrite rule of AdGuard Home."""

    # The domain to rewrite, which may be a wildcard like `*.example.com`.
    domain: str

    # What to answer with: an IP address, or a domain name for a CNAME.
    answer: str

    # Added in AdGuard Home v0.107.68. Older versions leave it out, and
    # always apply every rule.
    enabled: bool = True


class AdGuardHomeRewrite(Area):
    """DNS rewrites of AdGuard Home."""

    __slots__ = ()

    async def get(self) -> tuple[RewriteRule, ...]:
        """Return all DNS rewrite rules.

        Returns
        -------
            The DNS rewrite rules, in the order AdGuard Home has them.

        """
        response = await self._request("rewrite/list")
        return tuple(RewriteRule.from_api(entry) for entry in response or [])

    async def add(self, domain: str, answer: str) -> None:
        """Add a DNS rewrite rule.

        Args:
        ----
            domain: The domain to rewrite, like `*.example.com`.
            answer: An IP address, or a domain name for a CNAME.

        """
        await self._request(
            "rewrite/add",
            method="POST",
            json={"domain": domain, "answer": answer},
        )

    async def remove(self, domain: str, answer: str) -> None:
        """Remove a DNS rewrite rule.

        Args:
        ----
            domain: The domain of the rule to remove.
            answer: The answer of the rule to remove.

        """
        await self._request(
            "rewrite/delete",
            method="POST",
            json={"domain": domain, "answer": answer},
        )
