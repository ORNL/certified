# Inspect your certificates

## Export your identity certificate

Print your identity cert in base64-DER format, suitable for sending to a
signing authority or another party who needs to verify your identity:

```bash
certified get-ident > my_cert.b64
```

## Export your CA (signing) certificate

Print a JSON object containing your CA certificate, suitable for passing to
`certified add-service` on the other side:

```bash
certified get-signer > my_ca.json
# {"ca_cert": "<base64-DER>"}
```

## Inspect a certificate with openssl

```bash
# PEM file
openssl x509 -text -noout -in $VIRTUAL_ENV/etc/certified/id.crt

# Base64-DER (decode first)
certified get-ident | base64 -d | openssl x509 -inform DER -text -noout
```

## List known servers and clients

```bash
ls $VIRTUAL_ENV/etc/certified/known_servers/
ls $VIRTUAL_ENV/etc/certified/known_clients/
```

Each `*.yaml` file in `known_servers/` is a
[TrustedService](../reference/models.md#trustedservice) record.
Each `*.crt` file in `known_clients/` is a PEM-encoded CA or identity cert.
