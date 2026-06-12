# Key Management

!!! tip "Authentication vs authorisation"
    `certified` manages certificates for **authentication** (proving who you are
    over mTLS).  It also provides tools for using biscuit tokens so you can
    implement **authorisation** (deciding what callers may do) on top.
    See the [Authorization Model](authz.md).

One of the major stumbling blocks for public key infrastructure (PKI) is the
management of keys and certificates.  There need to be at least 2 separate keys
for each entity (1 for signing certificates, and 1 for authenticating TLS
connections).  As a user, you may want to create short-lived keys that expire
automatically — `certified` relies on certificate **expiry**, not CRL/OCSP
revocation, to bound the validity window of a key.  Expiry is simpler and
requires no revocation infrastructure; plan your `not_after` dates accordingly.

Different interacting parties may have different trust roots.  Thus, you will
probably have to store a chain of trust between your own certificates and each
different trust root that you obtain a signature from.

The `Certified` class takes a key-directory as its input argument.  If none is
given, it finds a directory depending on the first of the following environment
variables to be set:

  1. `$CERTIFIED_CONFIG`
  2. `$VIRTUAL_ENV/etc/certified`
  3. `/etc/certified`

Inside the base directory, `Certified` expects the following layout:

  - **main directory**: PEM-encoded private and public keys
    (similar to `.ssh/id_ed25519` and `id_ed25519.pub`)

    * `CA.key`, `CA.crt` — private and public signing keys

    * `id.key`, `id.crt` — end-entity identification key for
      establishing TLS connections and encryption

    * Since each certificate can be co-signed by multiple authorities, one
      subdirectory (named after each certificate) holds co-signed chain files.
      Each file is a **sequence of PEM blocks** — the leaf certificate followed
      by any intermediate certificates needed to reach a trusted root:

          CA/signerA.crt   # PEM chain: your CA cert + signerA cert
          id/signerA.crt   # PEM chain: your id cert + signerA cert

      Multiple files in this directory represent the same identity key, but
      authenticated via different signing authorities.

      When establishing a TLS connection to a server that trusts `some_signer`,
      use `--key id.key --crt id/some_signer.crt`.
      `Certified.Client` does this automatically.

  - **`known_servers`** — PEM-encoded trusted server certificates.

    * Names servers you want to access (similar to `.ssh/known_hosts`) as
      well as signing authorities trusted to sign server certificates for
      those you don't know directly (similar to cacerts).

  - **`known_clients`** — PEM-encoded trusted client certificates.

    * Clients whose certs (and all certs signed by them) are allowed to access
      any API started with `certified serve`
      (similar to `.ssh/authorized_keys`).

    * Adding a CA certificate here indirectly grants access to all clients
      holding a cert signed by that CA.

    !!! note
        Certificates establish *identity* — they say nothing about what an
        authenticated client is permitted to do.  Authorisation is handled
        entirely by the biscuit layer.  See [Authorization Model](authz.md).

## Supported Key Types

`certified` supports all modern elliptic-curve key types.  RSA is excluded
by design — too slow for short-lived key generation and superseded by ECC.

| Key type | Status | Notes |
|---|---|---|
| Ed25519 | ✅ Default | Fast, small keys, widely deployed |
| Ed448 | ✅ Supported | Higher security margin, less common |
| ECDSA P-256 | ✅ Supported | Broad TLS compatibility |
| ECDSA P-384 | ⏳ Planned | Not yet implemented |
| ECDSA P-521 | ⏳ Planned | Not yet implemented |
| RSA | ❌ Not supported | Excluded by design |

## Federated Trust

When two organisations need to grant each other's clients selective access,
they can cross-sign individual identity certificates — storing co-signed PEM
chains in the `id/` subdirectory.  See
[Cross-chain Trust](cross_chain_trust.md) for a worked example including
directory layout, service definition files, and a step-by-step trace of how
`Certified.Client` resolves and connects to a cross-org service.

## Rationale

Many strategies have been employed to manage keys, but are either
a) not comprehensive or b) not specialised for x509 interactions.

[GPG's gpgsm tool](https://www.gnupg.org/documentation/manuals/gnupg/Howto-Create-a-Server-Cert.html)
comes close.  It uses an internal database of private keys and signatures at
`$HOME/.gnupg`.  However, gnupg was designed for easier name-key pairings,
and all the extra x509 fields are an add-on.

Basic web infrastructure uses `/usr/share/ca-certificates/mozilla` from the
ca-certificates package to list out trust roots.  The letsencrypt project
sets up a file-layout for a series of webserver keys as they expire and are
renewed over time.

OpenSSH uses `$HOME/.ssh` and defines many of the same file types used here
(`authorized_keys`, `known_hosts`).  However, SSH is less disciplined about
server authentication and not set up for x509/TLS.  It also does not support
chain-of-trust models or key-scoped authorisation policies.

The present key management strategy is based on `actor_api`, which used a
single private key per entity and did not store signatures.  That model was
more static and defined its own non-standard TLS.

The myproxy project had a similar x509-compatible public/private key setup.
However, myproxy did not keep all private keys local to the machine where they
were generated.  Its design became complex because it used certificates to
*delegate authority* — which was a mistake.  Its certificate-signing support
was later deprecated.  Ultimately, its decline was caused by conflating
authentication and authorisation.  `certified` keeps these strictly separate:
certificates prove identity; [biscuit tokens](authz.md) carry authorisation.
