# Run an mTLS server

`certified serve` starts a uvicorn HTTPS server with mutual TLS configured
from your `certified/` directory.  All clients must present a certificate
trusted by a CA in `known_clients/`.

## Basic usage

```bash
certified serve my_api.server:app https://0.0.0.0:8443
```

`my_api.server:app` is the Python import path to your ASGI application object
(same format as uvicorn).

## With verbose logging

```bash
certified serve -v my_api.server:app   # info level
certified serve -vv my_api.server:app  # debug level (shows cert details)
```

## Equivalent uvicorn command

`certified serve` is equivalent to:

```bash
uvicorn \
    --ssl-keyfile   $cfg/id.key \
    --ssl-certfile  $cfg/id.crt \
    --ssl-cert-reqs 2 \
    --ssl-ca-certs  $cfg/known_clients \
    --host 0.0.0.0 --port 8443 \
    my_api.server:app
```

`--ssl-cert-reqs 2` enforces client certificate authentication.

## Programmatic API

```python
import asyncio
from certified import Certified

cert = Certified()
cert.serve("my_api.server:app", "https://127.0.0.1:8443")
```

## Accessing the client certificate in FastAPI

Use `certified.fast` dependencies to inspect the peer certificate:

```python
from fastapi import FastAPI
from certified.fast import PeerCert, ClientName

app = FastAPI()

@app.get("/whoami")
async def whoami(name: ClientName, cert: PeerCert):
    return {"name": name, "subject": str(cert.subject)}
```

See the [FastAPI integration reference](../reference/fast.md) for the full
dependency list.

## Trust roots

- **Server certificate**: `id.key` + `id.crt` from your config directory.
- **Accepted clients**: any cert whose issuing CA appears in `known_clients/`.
  Add a CA cert there to trust all identities it signs.

```bash
# Trust all clients signed by an external CA
certified add-client external-org external_ca.pem \
    --config $VIRTUAL_ENV/etc/certified
```
