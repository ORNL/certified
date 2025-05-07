import asyncio
from certified import Certified

cert = Certified()

headers = { "user-agent": "my-app/0.0.1",
            "Accept": "application/json" }

async def main():
    async with cert.ClientSession(
                        #base_url="https://127.0.0.1:8000",
                        base_url="https://login05.frontier.olcf.ornl.gov:4433",
                        headers=headers
                    ) as cli:
        resp = await cli.get("/echo/Hello world!")
        assert resp.status_code == 200
        print( await resp.json() )

asyncio.run(main())
