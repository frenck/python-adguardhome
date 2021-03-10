# pylint: disable=W0621
"""Asynchronous Python client for the AdGuard Home API."""

import asyncio

from adguardhome import AdGuardHome


async def main():
    """Show example how to get status of your AdGuard Home instance."""
    async with AdGuardHome(host="192.168.1.2") as adguard:
        version = await adguard.version()
        print("AdGuard version:", version)

        active = await adguard.protection_enabled()
        active = "Yes" if active else "No"
        print("Protection enabled?", active)

        active = await adguard.filtering.enabled()
        active = "Yes" if active else "No"
        print("Filtering enabled?", active)

        active = await adguard.parental.enabled()
        active = "Yes" if active else "No"
        print("Parental control enabled?", active)

        active = await adguard.safebrowsing.enabled()
        active = "Yes" if active else "No"
        print("Safe browsing enabled?", active)

        active = await adguard.safesearch.enabled()
        active = "Yes" if active else "No"
        print("Enforce safe search enabled?", active)


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
