# Call an mTLS API

Three ways to make mTLS-authenticated requests, from simplest to most flexible.

## `message` — command-line client

```bash
# GET request
message https://my-api:8443/notes

# POST with inline JSON body
message https://my-api:8443/notes '{"message": "hello"}'

# POST from a file
message https://my-api:8443/notes --json payload.json

# Custom method
message https://my-api:8443/notes -X DELETE

# Add headers
message https://my-api:8443/notes -H "Authorization: Bearer token"

# Pretty-print JSON response
message https://my-api:8443/notes --pp
```

`message` looks up `my-api` in `known_servers/` and substitutes the real URL
and certificate chain automatically.

## `curl` — manual cert wiring

When you need curl directly, wire the certs explicitly:

```bash
cfg=$VIRTUAL_ENV/etc/certified

curl --capath $cfg/known_servers \
     --cert   $cfg/id/Org1.crt \
     --key    $cfg/id.key \
     -H "Accept: application/json" \
     https://my-api:8443/notes
```

Use the appropriate chain file from `id/` (matching the signer the server
trusts).  For a server with no cross-signing, use `id.crt` directly.

## `Certified.Client` — synchronous (httpx)

```python
from certified import Certified

cert = Certified()
with cert.Client("https://my-api:8443") as http:
    r = http.get("/notes")
    r.raise_for_status()
    print(r.json())

    r = http.post("/notes", json={"message": "hello"})
    r.raise_for_status()
```

The base URL alias is resolved against `known_servers/` automatically.

## `Certified.ClientSession` — async (aiohttp)

```python
import asyncio
from certified import Certified

async def main():
    cert = Certified()
    async with cert.ClientSession("https://my-api:8443") as api:
        r = await api.get("/notes")
        assert r.status == 200
        print(await r.json())

        r = await api.post("/notes", json={"message": "hello"})
        assert r.status == 200

asyncio.run(main())
```

## How alias resolution works

Both `Client` and `ClientSession` call `lookup_server(hostname)`, which reads
`known_servers/<hostname>.yaml`.  If found:

1. The real `url` from the YAML replaces the alias in the request URL.
2. `get_chain_from(auths)` selects the right `id/<CA-name>.crt` chain.
3. The server CA from the `cert` field is pinned for verification.

See [Cross-chain Trust](../concepts/cross_chain_trust.md) for a detailed trace.
