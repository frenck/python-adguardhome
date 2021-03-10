# pylint: disable=W0621
"""Asynchronous Python client for the AdGuard Home API."""

import asyncio

from adguardhome import AdGuardHome


async def main():
    """Show example on stats from your AdGuard Home instance."""
    async with AdGuardHome("192.168.1.2") as adguard:
        version = await adguard.version()
        print("AdGuard version:", version)

        period = await adguard.stats.period()
        print("Stats period:", period)

        result = await adguard.stats.avg_processing_time()
        print("Average processing time per query in ms:", result)

        result = await adguard.stats.dns_queries()
        print("DNS queries:", result)

        result = await adguard.stats.blocked_filtering()
        print("Blocked DNS queries:", result)

        result = await adguard.stats.blocked_percentage()
        print("Blocked DNS queries ratio:", result)

        result = await adguard.stats.replaced_safebrowsing()
        print("Pages blocked by safe browsing:", result)

        result = await adguard.stats.replaced_parental()
        print("Pages blocked by parental control:", result)

        result = await adguard.stats.replaced_safesearch()
        print("Number of enforced safe searches:", result)

        result = await adguard.filtering.rules_count()
        print("Total number of active rules:", result)


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
