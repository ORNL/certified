# Cross-org introduction

The `introduce` / `add-intro` workflow is the recommended way to establish
cross-org trust.  It handles RFC 4514 distinguished-name strings automatically
— neither party ever needs to type or copy them.

See [Cross-chain Trust](../concepts/cross_chain_trust.md) for a detailed
explanation of what happens under the hood.

## Step 1 — Subject exports their identity cert

```bash
# On the subject's machine
certified get-ident > my_cert.b64
# Send my_cert.b64 to the signer out-of-band (email, git, etc.)
```

## Step 2 — Signer verifies and introduces

The signer must verify out-of-band that `my_cert.b64` really belongs to the
claimed subject — not an impostor.  Only then:

```bash
# On the signer's machine
certified introduce my_cert.b64 > intro.json
# Send intro.json back to the subject
```

The JSON output:
```json
{
  "signed_cert": "<base64-DER — subject's cert signed by signer's CA>",
  "ca_cert":     "<base64-DER — signer's CA cert>",
  "services": {
    "alias-name": "https://host:port"
  }
}
```

The optional `services` field is not produced automatically — the signer can
add it manually to the JSON before sending, listing service aliases the
subject should be able to reach with the new cross-org identity.

## Step 3 — Subject installs the introduction

```bash
# On the subject's machine
certified add-intro intro.json
```

This automatically:

1. Saves `id/<signer-RFC4514-name>.crt` — the signed PEM chain
2. Creates `known_servers/<alias>.yaml` for each entry in `services`,
   pre-populated with the correct CA cert and auth name

The subject can now authenticate to the signer's services using the new chain.

## Verify the result

```bash
ls $VIRTUAL_ENV/etc/certified/id/
# CN=Signer CA,O=Org2.crt  ← new entry

ls $VIRTUAL_ENV/etc/certified/known_servers/
# alias-name.yaml  ← new entry
```

## Security note

Once you run `introduce`, your CA's reputation is tied to the subject's key
hygiene.  If either condition is false —

1. The certificate is held by the actual subject (not an impostor)
2. The subject keeps their private key secret

— you will need to rotate your CA identity.
