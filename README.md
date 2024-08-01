# Certified

How do I know who originated an API request -- what organization
they come from, and what kinds of organizational policies they have
been asked to follow?

How can I consistently apply my own site's security policy
to API actions?

And -- the big question -- how can I, as a client using an API,
obtain, manage, and send these credentials to servers I interact
with?

The certified package has you covered.


# Proofs

Certificates are fundamentally about providing logical proofs
of facts using cryptographic.

## Definitions:

* authentication - proving that someone is who they claim to be

* authorization  - proving that an action is allowed within the current context

* intent         - proving that an action was intended by the requestor


## Pitfalls of tokens

The number one problem with tokens is that they are not
a reliable method of authentication.  Authentication must
be established when a network communication channel is opened --
for example during the TLS handshake between client and server.
Security conversations become much simpler within mutually
authenticated TLS channels -- since then each party has
established who it is talking to.

Other forms of authentication are subject to third-party
attack.  Tokens are especially vulnerable because
they are exchanged at the application level.
Any server that has observed a token has the potential
to re-use the token -- impersonating the original
sender of the request.

# Installation

As a user, install with

    pip install .

As a developer, install with:

    poetry install --with docs

Add new dependencies using, e.g.:

    poetry add pydantic          # run-time dependency
    poetry add mkdocs-material --group docs # documentation-generation dep.
    poetry add mypy            --group test # test-time dep.

# Usage

The certified.json file contains your `certified.Config`
data including:

  * `identity` -- your own identity as a client/server
  * `trusted_clients` -- clients allowed to access your API
  * `trusted_servers` -- API servers you wish to interact with

## API Client

To interact with an API server that requires mTLS,
you can instantiate an `APIClient` context object.
This context is an `httpx.Client` that bakes in the
appropriate client and server certificates so that
you can be sure you are interacting with the `trusted_server`
you requested.


## API Server

To run an API server, create an ASGI webserver application
class (e.g. using `app = FastAPI()` inside `my_api/server.py`),
and then start it with:

    certified start my_api.server:app [additional options]


This uses uvicorn internally and is equivalent to running:

    uvicorn --ssl-keyfile server.key --ssl-certfile server.pem \
            --ssl-cert-reqs 2 --ssl-ca-certs ca_root.pem \
            --host <ip_from_config> --port <port_from_config> \
            my_api.server:app [additional options]

where `--ssl-cert-reqs 2` is the magic argument needed to ensure clients
authenticate with TLS, and the other keys are created from pem-encoding
data from your server's `certified.json` config file.

We actually implement this internally with uvicorn's
[programmatic API](https://www.uvicorn.org/deployment/#running-programmatically).

    uvicorn.run("main:app", host="127.0.0.1", port=5000, log_level="info")


# Root CA-s

Generate a root certificate:
    python3 new_ca.py

Create a signed server and client certificate with it:
    python3 sign_cert.py -o server
    python3 sign_cert.py -i me@localhost -o client

Explanation -- the second command creates a cert.pem and cert.key
file which attests that the CA knows the identity listed in cert.pem.
The cert.key file is used during a TLS socket handshake to prove
that the identity in cert.pem belongs to them.

Start a test server using:

```
uvicorn --ssl-keyfile server.key --ssl-certfile server.pem \
        --ssl-cert-reqs 1 --ssl-ca-certs ca_root.pem \
        server:app
```

Securely query the server with:

    python3 client.py

or

    curl --cacert ca_root.pem --key client.key --cert client.pem https://127.0.0.1:8000/


# References

[x509]: https://cryptography.io/en/latest/x509/tutorial/#creating-a-certificate-signing-request-csr "Python x509 Cryptography HOWTO"
[openssl]: https://x509errors.org/guides/openssl "OpenSSL: TLS Guide" -- building a custom validator in C
[mtls]: https://www.golinuxcloud.com/mutual-tls-authentication-mtls/ "Mutual TLS"
[exts]: https://www.golinuxcloud.com/add-x509-extensions-to-certificate-openssl/ "Adding Extensions to x509"
[globus]: https://globus.stanford.edu/security.html

## more on custom attributes using openssl command

https://stackoverflow.com/questions/36007663/how-to-add-custom-field-to-certificate-using-openssl
https://stackoverflow.com/questions/17089889/openssl-x509v3-extended-key-usage -- config. file attributes
https://superuser.com/questions/947061/openssl-unable-to-find-distinguished-name-in-config/1118045 -- use a complete config
