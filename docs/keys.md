# Key Management

One of the major stumbling blocks for public key infrastructure
(PKI) is the management of keys and certificates.
There need to be at least 2 separate keys for each entity
(1 for signing certificates, and 1 for authenticating
TLS and/or encryption).  As a user, you may want to create
ephermal keys which you can revoke when you log out.

Different interacting parties may have different
trust roots.  Thus, you will probably have to
store a chain of trust between your own
certificates and each different trust root that you
obtain a signature from.

The `Certified` class takes a key-directory
as its input argument.  If none is given, it
finds a directory depending on the first of the following
environment variables to be set:

  1. `$CERTIFIED_CONFIG`

  2. `$VIRTUAL_ENV/etc/certified`

  3. `/etc/certified`

Inside the base directory, `Certified` expects
the following layout:

  - main directory: PEM-encoded private and public keys
    (similar to `.ssh/id_ed25519` and `id_ed25519.pub`)

    * CA.key, CA.crt -- private and public signing keys

    * id.key, id.crt   -- end-entity identification key for
                          establishing TLS connections and encryption

    * Since each certificate can be signed by others,
      one subdirectory (named after each certificate)
      holds signatures for that key from other authorities.

      e.g. `CA/signer[A,B,...].crt` and `id/signer[A,B,...].crt`

      - multiple public keys within this directory refer to the
        same identity, but are named after the CA that signed them.

      - When establishing a TLS connection to a server that
        trusts `some_signer`, you should use
        `--key id.key --crt id/some_signer.crt`
        `Certified.Client` and the `message` utility
        do this automatically.

  - `known_servers` -- PEM-encoded trusted server certificates.

    * these name servers you want to access
      (similar to `.ssh/known_hosts`)
      as well as signing authorities that we trust to sign
      server certificates for those we don't know directly
      (similar to cacerts)

    * TODO: we should add a config file to ea. specifying
      the URL to use and the server's trusted signers.

  - `known_clients` -- PEM-encoded trusted client certificates.

    * these (and all keys signed by them) are allowed to access
      any API you start with (certified start)
      (similar to `.ssh/authorized_keys`)

    * A `name.scope` file next to a `name.crt` file gives
      a newline-separated list of allowed scopes for
      clients authenticating via this cert.

    * Adding a certificate for a certificate authority
      to this directory provides a way to indirectly grant
      access to clients -- by validating they have a
      signature from this certificate authority.


    Note: It's unclear what to do about certificatePolicies
          present in these client certs.
          We choose to ignore them.
          That's because we don't expect to modify the certs,
          and would much prefer to manage allowed scopes
          by easily editable text files (`name.scope`).


## Rationale

Many strategies have been employed to manage keys, but are
either a) not comprehensive or b) not specialized for x509
interactions.

[GPG's gpgsm tool](https://www.gnupg.org/documentation/manuals/gnupg/Howto-Create-a-Server-Cert.html) comes close.  It uses an
internal database of private keys and signatures at `$HOME/.gnupg`.
However, gnupg was designed to use easier name-key pairings,
and so all the extra x509 fields are an add-on.  The docs
show the user managing the pem-encoded certificates and adding
extra configuration for things like key policies.

Basic web infrastructure uses `/usr/share/ca-certificates/mozilla`
from the ca-certificates package to list out trust roots,
and some custom directory, like `/etc/certificates` to store
server end-entity IDs.  For example, the letsencrypt project
sets up a file-layout for a series webserver keys (as
they expire and are renewed over time).

OpenSSH uses `$HOME/.ssh` and defines many of the same
file types we use here (`authorized_keys`, `known_hosts`).
However, they are less disciplined about server authentication
and not setup for use with x509 certificates needed by TLS.
They also do not support chain-of-trust models or
key policies (which we use for session scopes).

The present key management strategy is based on actor\_api, which
utilized a single private key per entity, and did not store
signatures.  That model was more static, and defined its own,
non-standard TLS.

The myproxy project has a similar x509-compatible
public/private key setup as here.  However, myproxy does not keep
all private keys local to the machine where they were
generated.  This design became complex because it
used certificates to delegate authority -- which
was a mistake.
Its support for certificate signing has been listed
as deprecated.  Ultimately, its decline was caused by
relying on certificates for authorization, when they
should only be used for authentication.
