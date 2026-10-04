# pylint: disable=W0621
"""Asynchronous Python client for the AdGuard Home API."""

import asyncio

from adguardhome import AdGuardHome


async def main() -> None:
    """Show example on stats from your AdGuard Home instance."""
    async with AdGuardHome("http://192.168.1.2:3000") as adguard:
        status = await adguard.status()
        print("AdGuard version:", status.version)

        config = await adguard.stats.config()
        print("Stats retention:", config.retention)

        stats = await adguard.stats.get()
        print("Average processing time:", stats.avg_processing_time)
        print("DNS queries:", stats.dns_queries)
        print("Blocked DNS queries:", stats.blocked_filtering)
        print(f"Blocked DNS queries ratio: {stats.blocked_percentage:.1f}%")
        print("Pages blocked by safe browsing:", stats.blocked_safebrowsing)
        print("Pages blocked by parental control:", stats.blocked_parental)
        print("Number of enforced safe searches:", stats.enforced_safesearch)
        print("Top queried domains:", list(stats.top_queried_domains)[:3])

        blocklists = await adguard.filtering.blocklists.list()
        rules = sum(
            blocklist.rules_count for blocklist in blocklists if blocklist.enabled
        )
        print("Total number of active blocklist rules:", rules)


if __name__ == "__main__":
    asyncio.run(main())
