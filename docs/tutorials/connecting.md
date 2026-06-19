## Tutorial 2 — Connecting with another organization

**Scenario:** Alice (ORNL) wants to call an API run by Bob Chen at NIST.
Bob's API server already exists and is configured with his own `certified`
identity.  Alice and Bob need to establish cross-org trust.

This is the `introduce` / `add-intro` workflow.
See [Cross-org introduction](../howto/introduce.md) and
[Cross-chain Trust](../concepts/cross_chain_trust.md) for the full picture.

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
