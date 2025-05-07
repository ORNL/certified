<!--This part of the project documentation focuses on a
**learning-oriented** approach. You'll learn how to
get started with the code in this project.

> **Note:** Expand this section by considering the
> following points:

- Help newcomers with getting started
- Teach readers about your library by making them
    write code
- Inspire confidence through examples that work for
    everyone, repeatably
- Give readers an immediate sense of achievement
- Show concrete examples, no abstractions
- Provide the minimum necessary explanation
- Avoid any distractions
-->

# Tutorial

## Writing a client

The aiohttp library provides a nice interface for
writing an API client.

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

This example queries the public
[National Weather Service API](https://www.weather.gov/documentation/services-web-api) to get the weather forecast
for Cape Canaveral, FL by specifying
its latitude, longitude pair.

The headers here are extra pieces of information sent along
with the request that are not part of the URL.
Some APIs (for example google photos) expect access
tokens to be passed in the headers.
In this example, both header values are optional,
since the server hasn't asked for this information specifically.

The `base_url` forms the prefix for all requests
using this client.  Our `get` call actually performs the
equivalent of:

    curl https://api.weather.gov/points/28.3968,-80.6057

By creating a client context object, we can avoid repeating
the base URL and headers with every request.

More examples of using aiohttp client methods are provided
in their [quick start guide](https://docs.aiohttp.org/en/stable/client_quickstart.html).


## Writing a server

To write your own server, I recommend
following the [FastAPI tutorial](https://fastapi.tiangolo.com/tutorial/first-steps/).  Here's an echo server:

    # examples/echo.py

    from typing import Dict
    from fastapi import FastAPI

    app = FastAPI()

    @app.get("/echo/{value}")
    async def echo(value : str) -> Dict[str, str]:
        return {"message": value}

You can run this with:

    uvicorn examples.echo:app

It runs by default on `http://127.0.0.1:8000`
and you can access it with, for example:

    curl http://127.0.0.1:8000/echo/Hello%20World%21

Note that it uses HTTP, [which is insecure](https://https.cio.gov/).
Serving only to 127.0.0.1 means the outside world can't access
it however.  So it is safe for the time being.

In order to transition this server to production,
we will need to

1. setup a server certificate so it can serve requests via HTTPS

2. grant clients certificates and/or tokens and setup the server
   to validate those


## Creating a certificate with certified

Creating a server certificate with certified is easy.

    certified init --org 'Test Org' --unit 'Software' \
                --host 127.0.0.1 --host localhost \
                --config my_id

This creates both a signing and an identity certificate
in a new directory named `my_id`.
See [explanation](explanation.md) for a full explanation.

## Running the server with Certified

    certified serve --config my_id examples.echo:app https://127.0.0.1:8000

If you access this server from your web browser,
you will get 2 connection errors.  First, your
browser will not trust the server.  Second, the server
will not trust your browser.


## Running the client with Certified

To access this server, you can use the command-line message utility
as you would for curl,

    message --config my_id https://127.0.0.1:8000/echo/hello

For more involved use cases, Certified provides a way to create
an aiohttp ClientSession.  This session is correctly wrapped
with the client ID and root certificates configured within your
configuration directory.

    import asyncio
    from certified import Certified

    cert = Certified("my_id")

    headers = { "user-agent": "my-app/0.0.1",
                "Accept": "application/json" }

    async def main():
        async with cert.ClientSession(
                            base_url="https://127.0.0.1:8000",
                        headers=headers
                        ) as cli:
            resp = await cli.get("/echo/Hello world!")
            assert resp.status_code == 200
            print( await resp.json() )

    asyncio.run(main())
