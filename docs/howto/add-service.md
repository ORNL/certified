# Add a known service

Register a remote service so `Certified.Client` and `message` can look it up
by alias and connect with the right certificate chain.

!!! tip
    Prefer [`introduce` / `add-intro`](introduce.md) for initial setup —
    it populates the service YAML automatically.  Use `add-service` when you
    have a server CA cert out-of-band and want to register the service manually.

## From a PEM file

```bash
# Export the server's CA cert (run on the server's machine)
openssl x509 -in $VIRTUAL_ENV/etc/certified/CA.crt > server_ca.pem

# Register on the client's machine
certified add-service my-api server_ca.pem \
    --config $HOME/etc/certified
```

This creates `known_servers/my-api.yaml` with:
- `url: https://my-api`
- `cert`: the base64-DER encoded server CA
- `auths`: the RFC 4514 subject name extracted from the CA cert (auto-added)

## From a JSON file (`get-signer` output)

```bash
# On the server
certified get-signer > server_ca.json

# On the client
certified add-service my-api server_ca.json \
    --config $HOME/etc/certified
```

## With a path prefix or non-standard port

The `NAME` argument becomes the service alias and the `https://` URL base.
To include a port or path prefix, use `host:port` or `host:port/prefix`:

```bash
certified add-service my-api:8443 server_ca.pem
# → url: https://my-api:8443

certified add-service my-api:8443/v1 server_ca.pem
# → url: https://my-api:8443/v1
```

When a client calls `message https://my-api:8443/endpoint`, the alias
`my-api:8443` is looked up and the real URL and cert are substituted.

## Adding extra auth names

If the server also accepts signatures from a *second* CA (in addition to the
one in `CRT`), append it with `--auth`:

```bash
certified add-service my-api server_ca.pem \
    --auth 'CN=Extra Signer,O=OtherOrg'
```

The RFC 4514 string must exactly match the CA's subject name.  Use
`openssl x509 -subject -noout -in ca.pem` to print it.
