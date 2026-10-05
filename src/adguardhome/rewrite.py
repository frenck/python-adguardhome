"""DNS rewrites of AdGuard Home."""

from __future__ import annotations

from dataclasses import dataclass, replace

from ._area import Area
from ._model import AdGuardHomeModel


@dataclass(frozen=True, kw_only=True)
class RewriteRule(AdGuardHomeModel):
    """A DNS rewrite rule of AdGuard Home."""

    # The domain to rewrite, which may be a wildcard like `*.example.com`.
    domain: str

    # What to answer with: an IP address, or a domain name for a CNAME.
    answer: str
    enabled: bool = True


@dataclass(frozen=True, kw_only=True)
class RewriteConfig(AdGuardHomeModel):
    """Configuration of DNS rewrites, for all rules at once."""

    enabled: bool


class AdGuardHomeRewrite(Area):
    """DNS rewrites of AdGuard Home.

    A rule is identified by its domain and answer together, so the same
    domain can have several answers.
    """

    __slots__ = ()

    async def get(self) -> tuple[RewriteRule, ...]:
        """Return all DNS rewrite rules.

        Returns
        -------
            The DNS rewrite rules, in the order AdGuard Home has them.

        """
        response = await self._request("rewrite/list")
        return tuple(RewriteRule.from_api(entry) for entry in response or [])

    async def add(self, domain: str, answer: str, *, enabled: bool = True) -> None:
        """Add a DNS rewrite rule.

        Args:
        ----
            domain: The domain to rewrite, like `*.example.com`.
            answer: An IP address, or a domain name for a CNAME.
            enabled: False to add the rule without applying it yet.

        """
        rule = RewriteRule(domain=domain, answer=answer, enabled=enabled)
        await self._request("rewrite/add", method="POST", json=rule.to_dict())

    # pylint: disable-next=too-many-arguments
    async def update(
        self,
        domain: str,
        answer: str,
        *,
        new_domain: str | None = None,
        new_answer: str | None = None,
        enabled: bool | None = None,
    ) -> None:
        """Change a DNS rewrite rule. Leave out what should stay the same.

        Args:
        ----
            domain: The current domain of the rule.
            answer: The current answer of the rule.
            new_domain: The new domain of the rule.
            new_answer: The new answer of the rule.
            enabled: True to apply the rule, False to stop applying it.

        """
        update: dict[str, str | bool] = {
            "domain": domain if new_domain is None else new_domain,
            "answer": answer if new_answer is None else new_answer,
        }

        # AdGuard Home keeps the current state when `enabled` is left out.
        if enabled is not None:
            update["enabled"] = enabled

        await self._request(
            "rewrite/update",
            method="PUT",
            json={"target": {"domain": domain, "answer": answer}, "update": update},
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

    async def config(self) -> RewriteConfig:
        """Return the configuration of DNS rewrites.

        Returns
        -------
            Whether AdGuard Home applies the rewrite rules at all.

        """
        return RewriteConfig.from_api(await self._request("rewrite/settings"))

    async def set_config(self, config: RewriteConfig) -> None:
        """Replace the configuration of DNS rewrites.

        Args:
        ----
            config: The new configuration of DNS rewrites.

        """
        await self._request(
            "rewrite/settings/update", method="PUT", json=config.to_dict()
        )

    async def enable(self) -> None:
        """Apply the enabled DNS rewrite rules."""
        await self.set_config(replace(await self.config(), enabled=True))

    async def disable(self) -> None:
        """Stop applying any DNS rewrite rule, without removing them."""
        await self.set_config(replace(await self.config(), enabled=False))
