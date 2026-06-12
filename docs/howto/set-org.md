# Join an organization

`certified set-org` converts a standalone identity into a managed member of
an existing organization.  It replaces your self-signed CA with the
organization's signed certificate and updates trust roots accordingly.

!!! danger "Destructive operation"
    This command **permanently removes** your CA private key and signing
    infrastructure.  After running it, you can no longer sign new certificates
    yourself.  Make sure you have a backup if you might need to revert.

    Removed:
    - `certified/CA.key`, `certified/CA.crt`
    - `certified/id/` (cross-signed identities)
    - `certified/CA/` (CA cross-signatures)
    - `certified/known_servers/self.crt`, `certified/known_clients/self.crt`

## Prerequisites

1. You have an existing identity created with `certified init`.
2. Your organization's administrator has run `certified introduce` on your
   `id.crt` and sent you an introduction JSON file.
3. Your existing `id.key` matches the public key in `signed_cert` from the
   introduction file.

## Run `set-org`

```bash
certified set-org intro.json --overwrite \
    --config $VIRTUAL_ENV/etc/certified
```

`--overwrite` is required — it is a deliberate safety gate.

## What happens

1. `id.crt` is replaced with the org-signed certificate from `signed_cert`.
2. The org's CA cert (`ca_cert`) is written to both:
   - `known_clients/org.crt` — accept connections from org members
   - `known_servers/org.crt` — trust the org's services
3. If the JSON includes a `services` dict, `known_servers/<alias>.yaml` files
   are created for each entry.
4. Self-signed infrastructure (CA keys, `id/`, `CA/`, `self.crt` files) is
   removed.

## After joining

Your identity is now a leaf certificate issued by the org CA.  You authenticate
to org services using `id.key` + `id.crt` (the org-signed cert).  You no
longer have a `CA.crt` to sign new identities.

```bash
# Verify the new identity
openssl x509 -text -noout -in $VIRTUAL_ENV/etc/certified/id.crt
```
