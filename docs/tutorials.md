# Tutorials

These tutorials walk you through the three core workflows in `certified`.
Each is self-contained; follow them in order or jump to the one you need.
The [How-To Guides](howto/index.md) cover each step in more detail.

---

## Tutorial 1 — Setting up an identity

**Scenario:** Alice Nguyen is a researcher at Oak Ridge National Laboratory.
She needs a `certified` identity so she can authenticate to internal APIs
and eventually connect with collaborators at other institutions.

### 1. Create your identity

```bash
certified init 'Alice Nguyen' \
    --email alice.nguyen@ornl.gov \
    --config $HOME/etc/certified
```

This creates a config directory with a CA key, an identity cert, and
self-trust entries so Alice can immediately call her own services.
See [Create an identity](howto/init.md) for all available options.

### 2. Inspect what was created

```bash
ls $HOME/etc/certified/
# CA.key  CA.crt  id.key  id.crt  known_servers/  known_clients/
```

Export the identity cert in base64-DER (for sharing with a signer):

```bash
certified get-ident --config $HOME/etc/certified
```

### 3. Run a quick self-test

Start a minimal echo server using your new identity:

```bash
certified serve --config $HOME/etc/certified examples.echo:app https://127.0.0.1:8443
```

Then call it from another terminal:

```bash
certified message --config $HOME/etc/certified https://127.0.0.1:8443/echo/hello
```

If the server responds, your certificate stack is working end-to-end.

---

## Tutorial 2 — Connecting with another organization

**Scenario:** Alice (ORNL) wants to call an API run by Bob Chen at NIST.
Bob's API server already exists and is configured with his own `certified`
identity.  Alice and Bob need to establish cross-org trust.

This is the `introduce` / `add-intro` workflow.
See [Cross-org introduction](howto/introduce.md) and
[Cross-chain Trust](concepts/cross_chain_trust.md) for the full picture.

### Step 1 — Alice exports her identity cert

```bash
# Alice's machine
certified get-ident --config $HOME/etc/certified > alice_cert.b64
# Send alice_cert.b64 to Bob out-of-band (email, Slack, etc.)
```

### Step 2 — Bob verifies and introduces

Bob checks (out-of-band) that the cert really belongs to Alice, then:

```bash
# Bob's machine
certified introduce alice_cert.b64 > intro.json
```

Bob can optionally add the `"services"` field to `intro.json` so Alice's
client is automatically configured for his API:

```json
{
  "signed_cert": "...",
  "ca_cert": "...",
  "services": {
    "nist-materials-api": "https://materials.nist.gov:8443"
  }
}
```

Bob sends `intro.json` back to Alice.

### Step 3 — Alice installs the introduction

```bash
# Alice's machine
certified add-intro intro.json --config $HOME/etc/certified
```

`add-intro` automatically:

- Saves the signed cert chain under `id/<Bob's-org-name>.crt`
- Creates `known_servers/nist-materials-api.yaml` pre-populated with Bob's
  CA cert and the correct auth name

Alice can now call Bob's API without any manual RFC 4514 string handling:

```bash
certified message --config $HOME/etc/certified \
    https://materials.nist.gov:8443/datasets
```

---

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
See the [FastAPI integration reference](reference/fast.md) for more dependencies.

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

See [Trust a client](howto/add-client.md) for details.

### 4. Start the server

```bash
certified serve \
    --config $VIRTUAL_ENV/etc/certified \
    ornl_api.server:app \
    https://0.0.0.0:8443
```

Bob can now call Alice's API using the cross-org identity he issued her in
Tutorial 2, and the `ClientName` dependency will greet him by name.

For structured JSON logging, see [Rich JSON logging](howto/logging.md).
