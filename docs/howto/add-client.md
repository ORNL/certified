# Trust a client

Add a certificate to `known_clients/` so the server accepts connections from
that identity (or any identity signed by that CA).

## Trust a CA (recommended)

Adding a CA certificate trusts all end-entity certificates it signs, including
future ones.  This is the typical choice for granting access to an org's users:

```bash
# Copy the client org's CA cert to your known_clients
cp /path/to/client_ca.pem \
   $VIRTUAL_ENV/etc/certified/known_clients/client-org.crt
```

Or via the CLI:

```bash
certified add-client client-org /path/to/client_ca.pem \
    --config $VIRTUAL_ENV/etc/certified
```

## Trust a specific end-entity

!!! warning
    TLS validation does not permit trusting self-signed end-entity certificates
    directly.  To trust a specific person, add their CA cert instead.

## Using the introduction workflow instead

For cross-org access, the [`introduce` / `add-intro`](introduce.md) workflow
is easier: the signer runs `introduce` and the subject runs `add-intro`, which
installs the signed cert on the subject's side.  On the *server* side, the
server already trusts all certs signed by its own CA; to additionally trust
an external client, add that client's CA:

```bash
certified add-client external-org external_ca.pem \
    --config $VIRTUAL_ENV/etc/certified
```

## Scopes (metadata only)

The `SCOPES` argument stores a whitespace-separated scope list alongside the
cert entry.  These are metadata — the server does **not** enforce them
automatically.  Wire them into your authorisation logic via the
[`certified.fast`](../reference/fast.md) FastAPI integration.

```bash
certified add-client partner-org partner_ca.pem "read write" \
    --config $VIRTUAL_ENV/etc/certified
```
