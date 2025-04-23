[![CI](https://github.com/ORNL/certified/actions/workflows/python-package.yml/badge.svg)](https://github.com/ORNL/certified/actions)
[![Docs](https://readthedocs.org/projects/certified/badge/)](https://certified.readthedocs.io)
[![Coverage](https://codecov.io/github/ORNL/certified/branch/main/graph/badge.svg)](https://app.codecov.io/gh/ORNL/certified)


# Certified

An idiomatic framework for using certificates
and cookies (macaroons/biscuits) within python web API-s.

We make the following design choices:

* mTLS - mutual transport layer certificates (x509) authenticate
  client and server to one another

* scopes - clients can "prove" they have access to a scope
  (e.g. admin) by including it within their 'certificatePolicies'
  *at the handshake* phase

* tokens/cookies - we rely on the [datalog model of biscuits](https://doc.biscuitsec.org/reference/datalog)
  to exchange cookies that carry authorization proofs.
  Tokens, not certificates are used to delegate authorization.

* symmetry - symmetric ideas are used for setting up
  mutual identity verification (authentication) between
  client and server.  This allows servers to act as clients
  in complex workflows, and clients to act as servers
  to run callbacks.

* key management - we prescribe a file layout for these.
  Key file-names serve as a short-hand for referencing a
  given client/server.  See [docs/keys](docs/keys.md).


---

How do I know who originated an API request -- what organization
they come from, and what kinds of organizational policies they have
been asked to follow?

How can I consistently apply my own site's security policy
to API actions?

And -- the big question -- how can I, as a client using an API,
obtain, manage, and send these credentials to servers I interact
with?

The certified package has you covered.


See [documentation](docs) for explanations and howto-s.

# License

Certified is available under a 3-clause BSD-style license,
available in the file LICENSE.

Portions of certified (as marked in the code) are derived
from [python-trio/trustme](https://github.com/python-trio/trustme),
and are made available under the MIT license
-- as reproduced within those files.

# Installation

As a user, install with

    pip install .

## For development

As a developer, install with:

    poetry install --with docs,test

Add new dependencies using, e.g.:

    poetry add pydantic          # run-time dependency
    poetry add mkdocs-material --group docs # documentation-generation dep.
    poetry add mypy            --group test # test-time dep.

Run tests with:

    poetry run mypy .
    poetry run pytest

Preview the documentation with:

    poetry run mkdocs serve &

# Docs

Documentation was built using [this guide](https://realpython.com/python-project-documentation-with-mkdocs/) -- which comes highly recommended.

# Roadmap

* v0.8.1

  - [x] use base64-encoded DER for storing keys in yaml files.

  - [x] select certificate chain to send to server based on
    server name (test server configs.)

* v0.9.0

  - [X] better logging

  - [X] simpler introduction methodology

  - [X] readthedocs integration

  - [X] biscuit examples

* v0.10.0

  - [X] more feature-ful 'message' function

  - [X] add docs on how to use openssl to decode certificate contents

  - [X] configurable `biscuit_sec.Authorizor`-based biscuit auth

  - [X] better user experience with add-intro (now adds services)

  - [X] better user experience with add-service (will look for json with `ca_cert`)

  - [X] better user experience setting up org-level microservice
        `certified set-org`

* v1.0.0

  - [x] replace httpx with aiohttp (has better test client/server support).

  - [x] change servers to services where appropriate

* v1.0.2

  - [ ] throw warning if id.crt does not contain the server's
    hostname in SAN (since this will usually result in a connection error
    from SSL)

* v1.0.10

  - [ ] CI and better test coverage

  - [ ] better documentation for known\_services
        and interface for showing configuration contents

* v 1.1.0

  - [ ] Better documentation and more helpful error messages

  - [ ] Demo presentations and lessons learned

  - [ ] CLI interface for biscuit creation / validation

* v1.2.0

  - [ ] add certificate serial numbers

  - [ ] save a log of all certificates signed and revoked
    utilize CSR-s?
    https://cryptography.io/en/latest/x509/tutorial/#creating-a-certificate-signing-request-csr

  - [ ] support nng TLS sockets

  - [ ] support GRPC library

* v1.3.0

  - [ ] key rotation features and docs

## Technology to watch

- hardware certificate implementations (plug-ins?)

- OAuth2 integrations / biscuit adoption

# List of Useful Microservices

* <https://gitlab.com/frobnitzem/planner_api>

* <https://github.com/frobnitzem/psik_api>

* <https://gitlab.com/frobnitzem/signer>

# References

[mtls]: https://www.golinuxcloud.com/mutual-tls-authentication-mtls/ "Mutual TLS"

[x509]: https://cryptography.io/en/latest/x509/tutorial/#creating-a-certificate-signing-request-csr "Python x509 Cryptography HOWTO"

[openssl]: https://x509errors.org/guides/openssl "OpenSSL: TLS Guide" -- building a custom validator in C

[exts]: https://www.golinuxcloud.com/add-x509-extensions-to-certificate-openssl/ "Adding Extensions to x509"

[globus]: https://globus.stanford.edu/security.html

## Use of TLS/certs in services

[uvicorn]: https://github.com/encode/uvicorn/discussions/2307

[rucio transfers]: https://rucio.cern.ch/documentation/operator/transfers/transfers-overview/

[fts3 logging setup (enables TLS)]: https://fts3-docs.web.cern.ch/fts3-docs/docs/install/messaging.html

[fts3 tls]: https://fts3-docs.web.cern.ch/fts3-docs/docs/developers/tls_shenanigans.html

## more on custom attributes using openssl command

- https://stackoverflow.com/questions/36007663/how-to-add-custom-field-to-certificate-using-openssl

- https://stackoverflow.com/questions/17089889/openssl-x509v3-extended-key-usage -- config. file attributes

- https://superuser.com/questions/947061/openssl-unable-to-find-distinguished-name-in-config/1118045 -- use a complete config

## More on JWT/cookies/macaroons/biscuits

[scitokens]: https://scitokens.org/

[scitokens proposal]: https://scitokens.org/scitokens-proposal-public.pdf

[scitokens presentation]: https://scitokens.org/presentations/SciTokens-GDB-Oct-2017.pdf
o

[Indigo IAM JWT profiles]: https://indigo-iam.github.io/v/v1.9.0/docs/reference/configuration/jwt-profiles/

