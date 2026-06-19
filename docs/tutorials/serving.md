## Tutorial 3 — Running an mTLS API server

**Scenario:** Alice wants to expose her own API at ORNL so that trusted
collaborators (like Bob) can call it.

### 1. Write a FastAPI application

```python
# ornl_api/server.py
from fastapi import FastAPI
from certified.fast import ClientName

app = FastAPI()

@app.get("/hello")
async def hello(name: ClientName):
    return {"message": f"Hello, {name}!"}
```

`ClientName` is a FastAPI dependency that extracts the caller's common name
from the mTLS peer certificate — no manual cert parsing needed.
See the [FastAPI integration reference](../reference/fast.md) for more dependencies.

### 2. Add Alice's service identity

If Alice's personal identity is already set up (Tutorial 1), she can
create a separate service identity for her API server:

```bash
certified init \
    --org 'Oak Ridge National Laboratory' --unit 'Materials Science' \
    --domain materials.ornl.gov \
    --host materials.ornl.gov --host localhost \
    --email ops@ornl.gov \
    --config $VIRTUAL_ENV/etc/certified
```

### 3. Trust Bob's certificate

For Bob to call Alice's API, his CA must appear in `known_clients/`:

```bash
# Bob exports his CA cert:  certified get-signer > bob_ca.json
# Alice installs it:
certified add-client bob-nist bob_ca.json \
    --config $VIRTUAL_ENV/etc/certified
```

See [Trust a client](../howto/add-client.md) for details.

### 4. Start the server

```bash
certified serve \
    --config $VIRTUAL_ENV/etc/certified \
    ornl_api.server:app \
    https://0.0.0.0:8443
```

Bob can now call Alice's API using the cross-org identity he issued her in
Tutorial 2, and the `ClientName` dependency will greet him by name.

For structured JSON logging, see [Rich JSON logging](../howto/logging.md).
