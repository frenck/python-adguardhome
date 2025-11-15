# pylint: disable=W0621
"""Asynchronous Python client for the AdGuard Home API."""

import asyncio

from adguardhome import AdGuardHome


async def main() -> None:
    """Show example on controlling your AdGuard Home instance."""
    async with AdGuardHome("192.168.1.2") as adguard:
        version = await adguard.version()
        print("AdGuard version:", version)

        print("Turning off protection...")
        await adguard.disable_protection()

        active = await adguard.protection_enabled()
        yes_no = "Yes" if active else "No"
        print("Protection enabled?", yes_no)

        print("Turning on protection")
        await adguard.enable_protection()

        active = await adguard.protection_enabled()
        yes_no = "Yes" if active else "No"
        print("Protection enabled?", yes_no)


if __name__ == "__main__":
    asyncio.run(main())
