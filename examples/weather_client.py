# A simple client to read the weather at a geo-point.
#
# References:
#  - [National Weather Service API](https://www.weather.gov/documentation/services-web-api) to get the weather f
#  - [HTTPX quick start guide](https://www.python-httpx.org/quickstart/)
#
"""
import httpx

headers = { "user-agent": "my-app/0.0.1",
            "Accept": "application/json" }

with httpx.Client(base_url="https://api.weather.gov",
                  headers=headers) as cli:
    resp = cli.get("points/28.3968,-80.6057")
    assert resp.status_code == httpx.codes.OK
    print( resp.json() )
"""

import asyncio
import aiohttp

headers = { "user-agent": "my-app/0.0.1",
            "Accept": "application/json" }

async def main():
    async with aiohttp.ClientSession(
                base_url="https://api.weather.gov",
                headers=headers) as session:
        async with session.get("/points/28.3968,-80.6057") as resp:
            assert resp.status == 200
            print(await resp.json())

asyncio.run(main())
