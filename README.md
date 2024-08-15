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
  This makes use of [scitokens](https://scitokens.org/).

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


See [documentation][docs] for explanations and howto-s.

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

Documentation was built using [this guide](https://realpython.com/python-project-documentation-with-mkdocs/) -- which comes highly recommended:

# References

[x509]: https://cryptography.io/en/latest/x509/tutorial/#creating-a-certificate-signing-request-csr "Python x509 Cryptography HOWTO"
[openssl]: https://x509errors.org/guides/openssl "OpenSSL: TLS Guide" -- building a custom validator in C
[mtls]: https://www.golinuxcloud.com/mutual-tls-authentication-mtls/ "Mutual TLS"
[exts]: https://www.golinuxcloud.com/add-x509-extensions-to-certificate-openssl/ "Adding Extensions to x509"
[globus]: https://globus.stanford.edu/security.html

## Use of TLS/certs in services

[uvicorn]: https://github.com/encode/uvicorn/discussions/2307
[rucio transfers]: https://rucio.cern.ch/documentation/operator/transfers/transfers-overview/
[fts3 logging setup (enables TLS)]: https://fts3-docs.web.cern.ch/fts3-docs/docs/install/messaging.html

[fts3 tls]: https://fts3-docs.web.cern.ch/fts3-docs/docs/developers/tls_shenanigans.html

## more on custom attributes using openssl command

https://stackoverflow.com/questions/36007663/how-to-add-custom-field-to-certificate-using-openssl
https://stackoverflow.com/questions/17089889/openssl-x509v3-extended-key-usage -- config. file attributes
https://superuser.com/questions/947061/openssl-unable-to-find-distinguished-name-in-config/1118045 -- use a complete config

## More on JWT/cookies/macaroons/biscuits

[scitokens proposal]: https://scitokens.org/scitokens-proposal-public.pdf

[scitokens presentation]: https://scitokens.org/presentations/SciTokens-GDB-Oct-2017.pdf

[Indigo IAM JWT profiles]: https://indigo-iam.github.io/v/v1.9.0/docs/reference/configuration/jwt-profiles/

