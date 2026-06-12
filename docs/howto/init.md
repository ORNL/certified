# Create a new identity

Every `certified/` config directory represents one unique identity — one CA
signing key and one end-entity key.  Create separate directories for each
person and each microservice.

## Personal identity

```bash
certified init 'First Last' \
    --email name@my.org \
    --config $HOME/etc/certified
```

## Service / microservice identity

Services need at least one `--host` that matches the hostname clients will
connect to.

```bash
certified init \
    --org 'My Company' --unit 'My Org Unit' \
    --domain my-api.org \
    --host '*.my-api.org' --host 'localhost' \
    --email 'ops@my-api.org' \
    --config $VIRTUAL_ENV/etc/certified
```

`--org` and `--unit` are mutually exclusive with the positional name argument.

## What gets created

```
$VIRTUAL_ENV/etc/certified/
├── CA.key            # CA private key  (mode 0o600)
├── CA.crt            # CA certificate
├── id.key            # identity private key  (mode 0o600)
├── id.crt            # identity certificate
├── known_servers/
│   └── self.crt      # trusts your own CA for outbound connections
└── known_clients/
    └── self.crt      # trusts your own CA for inbound connections
```

## Inspect the result

```bash
openssl x509 -text -noout -in $VIRTUAL_ENV/etc/certified/id.crt
```

Or export your identity cert for sharing:

```bash
certified get-ident --config $VIRTUAL_ENV/etc/certified
```
