# pylint: disable=W0621
"""Asynchronous Python client for the AdGuard Home API."""

import json
import asyncio

from adguardhome import AdGuardHome


async def main():
    """Show example on controlling your AdGuard Home instance."""
    async with AdGuardHome("192.168.1.2") as adguard:
        version = await adguard.version()
        print("AdGuard version:", version)

        print("Getting configured client names...")
        client_names = await adguard.clients.getClientNames()
        print(client_names)

        print("Getting configured client configs...")
        clients = await adguard.clients.getClients()
        print(json.dumps(clients, sort_keys=False, indent=4))

        if len(client_names) > 0:                
            client_name = client_names[0]
            print(f"Getting settings for first client in list: ({client_name})...")
            
            client = adguard.clients.getClient(client_name)
            client_config = await client.getConfig()
            print(json.dumps(client_config, sort_keys=False, indent=4))
                        
            print("Disabling parental protection")
            await client.setParental(False)
            
            client_config = await client.getConfig()
            print(json.dumps(client_config, sort_keys=False, indent=4))
            
            print("Enabling parental protection")
            await client.setParental(True)
            
            client_config = await client.getConfig()
            print(json.dumps(client_config, sort_keys=False, indent=4))
        
        else:
            print("No clients configured to perform demo...")

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
