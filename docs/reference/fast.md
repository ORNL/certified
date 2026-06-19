# certified.fast — FastAPI Integration

Requires the `http` extra (`pip install 'certified[http]'`).

Provides FastAPI dependencies for extracting peer certificate info and
authorizing requests via [biscuit tokens](../concepts/authz.md).

## Peer certificate dependencies

### get_peercert

::: certified.fast.get_peercert

### get_remote_addr

::: certified.fast.get_remote_addr

### get_clientname

::: certified.fast.get_clientname

### name_from_peer

::: certified.fast.name_from_peer

`PeerCert` and `ClientName` are `Annotated` type aliases suitable for use
as FastAPI dependency parameters:

```python
from certified.fast import PeerCert, ClientName

@app.get("/info")
async def info(peer: PeerCert, name: ClientName):
    return {"name": name, "cert": peer}
```

## Biscuit token issuance

### Baker

::: certified.fast.Baker

## Biscuit token authorization

### BiscuitAuthz

::: certified.fast.BiscuitAuthz

### Critic

::: certified.fast.Critic

### run_authz

::: certified.fast.run_authz

### AuthMethod

::: certified.fast.AuthMethod
