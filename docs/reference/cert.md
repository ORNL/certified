# certified.cert — Certified

The `Certified` class is the main entry point for the library.
It reads a [config directory](../concepts/keys.md) and provides:

- SSL context creation for mTLS clients and servers
- Async (`aiohttp`) and sync (`httpx`) HTTP client context managers
- A uvicorn-based HTTPS server launcher
- Management of known clients, services, and identities

## Certified

::: certified.cert.Certified

## replace_baseurl

::: certified.cert.replace_baseurl
