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

        print("Getting configured clients...")
        clients = await adguard.clients.getClients()
        print(json.dumps(clients, sort_keys=False, indent=4))

        if len(clients) > 0:                
            client_name = clients[0]["name"]
            print(f"Getting settings for first client in list: ({client_name})...")
            
            client_config = await adguard.clients.getClient(client_name)
            print(json.dumps(client_config, sort_keys=False, indent=4))
                        
            print("Disabling parental protection")
            await adguard.clients.setClientParental(client_name, False)
            
            client_config = await adguard.clients.getClient(client_name)
            print(json.dumps(client_config, sort_keys=False, indent=4))
            
            print("Enabling parental protection")
            await adguard.clients.setClientParental(client_name, True)
            
            client_config = await adguard.clients.getClient(client_name)
            print(json.dumps(client_config, sort_keys=False, indent=4))
        
        else:
            print("No clients configured to perform demo...")

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
