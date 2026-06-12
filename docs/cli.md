# Installation

This package can be installed with [uv](https://docs.astral.sh/uv/) (recommended)
or pip.

**uv** (recommended):

    uv add 'certified[http]'

To install all optional extras (HTTP client/server support + docs):

    uv sync --all-extras

**pip**:

    pip install 'certified[http]'


## Command-Line Interface

Two commands are installed with certified: a main interface to certificate
management and microservice startup (`certified`), and a client for sending
mTLS-authenticated HTTP requests (`message`).

### `certified`

```
 Usage: certified [OPTIONS] COMMAND [ARGS]...

╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --install-completion          Install completion for the current shell.      │
│ --show-completion             Show completion for the current shell, to copy │
│                               it or customize the installation.              │
│ --help                        Show this message and exit.                    │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ───────────────────────────────────────────────────────────────────╮
│ init          Create a new signing and end-entity ID.                        │
│ add-client    Add the client directly to your `known_clients` list.          │
│ add-service   Add a service directly to your `known_servers` list.           │
│ introduce     Sign the subject's certificate and print a JSON introduction   │
│               to stdout.                                                     │
│ add-intro     Install an introduction produced by a remote `certified        │
│               introduce` call.                                               │
│ set-org       Setup this instance as a member of the signing organization.   │
│ get-ident     Create a json copy of my certificate suitable for sending to a │
│               signing authority.                                             │
│ get-signer    Create a json copy of my signing certificate.                  │
│ serve         Run the web server with HTTPS certificate-based trust setup.   │
╰──────────────────────────────────────────────────────────────────────────────╯
```

#### `certified init`

Create a new CA signing key and end-entity identity certificate.
The config directory defaults to `$VIRTUAL_ENV/etc/certified` but can be
overridden with `--config` or the `CERTIFIED_CONFIG` environment variable.

Either a person name (positional argument) or `--org` + `--unit` must be
provided, along with at least one of `--host`, `--email`, or `--uri`.

```
 Usage: certified init [OPTIONS] [NAME]

 Create a new signing and end-entity ID.

╭─ Person Name ────────────────────────────────────────────────────────────────╮
│   name      [NAME]  Note, name parsing into given and surnames and           │
│                     generations, etc. is not supported.                      │
│                     Examples:     - Timothy T. Tester                        │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --uid                            TEXT  System user name                      │
│ --domain                         TEXT  Domain components (.-separated)       │
│ --country                        TEXT                                        │
│ --state                          TEXT                                        │
│ --city                           TEXT                                        │
│ --overwrite    --no-overwrite          Overwrite existing config.            │
│                                        [default: no-overwrite]               │
│ --config                         PATH  Config file path [default             │
│                                        $VIRTUAL_ENV/etc/certified].          │
│ --help                                 Show this message and exit.           │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Organization Name ──────────────────────────────────────────────────────────╮
│ --org        TEXT  If specified, unit must also be present and name cannot   │
│                    be present. Example: 'Certificate Lab, Inc.'"             │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Organization Unit ──────────────────────────────────────────────────────────╮
│ --unit        TEXT  If specified, org must also be present and name cannot   │
│                     be present. Example: 'Computing Directorate'             │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Example: example@example.org ───────────────────────────────────────────────╮
│ --email        TEXT  email addresses                                         │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ host names ─────────────────────────────────────────────────────────────────╮
│ --host        TEXT  Examples: - "*.example.org" - "example.org" -            │
│                     "éxamplë.org" - "xn--xampl-9rat.org" - "127.0.0.1" -     │
│                     "::1" - "10.0.0.0/8" - "2001::/16"                       │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ uniform resource identifiers ───────────────────────────────────────────────╮
│ --uri        TEXT  Example: https://datatracker.ietf.org/…                  │
╰──────────────────────────────────────────────────────────────────────────────╯
```

#### `certified serve`

Run a FastAPI/Starlette ASGI application with mTLS enforced by certified.
The server reads its certificate and client trust roots from the config directory.

```
 Usage: certified serve [OPTIONS] APP [URL]

 Run the web server with HTTPS certificate-based trust setup.

╭─ Server's ASGI application ──────────────────────────────────────────────────╮
│ *    app      TEXT  Example: path.to.module:attr [required]                  │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ URL to serve application ───────────────────────────────────────────────────╮
│   url      [URL]  Example: https://127.0.0.1:8000                            │
│                   [default: https://0.0.0.0:4433]                            │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --loki             TEXT  json file containing url,user,passwd for sending    │
│                          logs to loki                                        │
│           -v             show info-level logs                                │
│           -vv            show debug-level logs                               │
│ --config           PATH  Config file path [default                           │
│                          $VIRTUAL_ENV/etc/certified].                        │
│ --help                   Show this message and exit.                         │
╰──────────────────────────────────────────────────────────────────────────────╯
```

#### `certified get-ident` / `certified get-signer`

Export your certificates for sharing with other parties.

- `get-ident` — prints your identity certificate (base64-DER), suitable for
  sending to a signing authority that will run `introduce` on it.
- `get-signer` — prints a JSON object `{"ca_cert": "..."}` containing your CA
  certificate, suitable for passing to `add-service` on the other side.

#### `certified introduce` / `certified add-intro`

The recommended workflow for establishing cross-org trust.  It resolves the
otherwise painful problem of RFC 4514 distinguished-name strings: the signer
never types them; the subject never sees them.

**How it works:**

1. **Subject** sends their identity certificate to the signer:
   ```
   certified get-ident > my_cert.b64
   # send my_cert.b64 to the signer out-of-band
   ```

2. **Signer** verifies the subject is who they claim to be, then runs:
   ```
   certified introduce my_cert.b64 > intro.json
   # send intro.json back to the subject
   ```
   The JSON response contains:
   ```json
   {
     "signed_cert": "<base64-DER — subject's cert signed by signer's CA>",
     "ca_cert":     "<base64-DER — signer's CA cert>",
     "services":    {"alias": "https://host:port", ...}  // optional
   }
   ```
   The `services` field, if included by the signer, lists service endpoints
   the subject should be able to reach using the new cross-org identity.

3. **Subject** installs the introduction in one command:
   ```
   certified add-intro intro.json
   ```
   This automatically:
   - Saves `id/<signer-RFC4514-name>.crt` (the signed PEM chain)
   - Creates `known_servers/<alias>.yaml` for each entry in `services`,
     pre-populated with the correct CA cert and auth name

   No RFC 4514 string handling required.

```
 Usage: certified introduce [OPTIONS] CRT

 Sign the subject's certificate and print a JSON introduction to stdout.
 ...

╭─ Arguments ──────────────────────────────────────────────────────────────────╮
│ *    crt      PATH  Subject's certificate. [required]                        │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --config        PATH  Config file path [default $VIRTUAL_ENV/etc/certified]. │
│ --help                Show this message and exit.                            │
╰──────────────────────────────────────────────────────────────────────────────╯
```

```
 Usage: certified add-intro [OPTIONS] SIGNATURE

 Install an introduction produced by a remote `certified introduce` call.
 ...

╭─ Arguments ──────────────────────────────────────────────────────────────────╮
│ *    signature      PATH  json signature response containing both            │
│                           "signed_cert" and "ca_cert". [required]            │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --overwrite    --no-overwrite          Overwrite existing authorization?     │
│                                        [default: no-overwrite]               │
│ --config                         PATH  Config file path [default             │
│                                        $VIRTUAL_ENV/etc/certified].          │
│ --help                                 Show this message and exit.           │
╰──────────────────────────────────────────────────────────────────────────────╯
```

#### `certified add-service`

Directly add a known server without the introduction workflow.  Useful when
you already have the server's CA certificate out-of-band.

The `CRT` argument accepts a PEM file, a base64-DER string, or a JSON file
with a `ca_cert` field (the format produced by `get-signer` or `introduce`).

The `--auth` option is for the RFC 4514 distinguished name of an additional
signing authority.  The CA cert's own RFC 4514 name is always appended
automatically, so `--auth` is only needed when the server accepts signatures
from CAs *other* than the one in `CRT`.

!!! tip
    Prefer `introduce` / `add-intro` for initial setup — it handles the RFC
    4514 names and service definitions for you.

```
 Usage: certified add-service [OPTIONS] NAME CRT

 Add a service directly to your `known_servers` list.
 ...

╭─ Arguments ──────────────────────────────────────────────────────────────────╮
│ *    name      TEXT  Service's hostname[:port][/path-prefix]. [required]     │
│ *    crt       PATH  Service's public signing certificate (PEM or b64-DER or │
│                      json with 'ca-root'). [required]                        │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --auth                           TEXT  rfc4514 name of an authorizor whose   │
│                                        signature would be recognized for     │
│                                        authenticating to this server.        │
│ --overwrite    --no-overwrite          Overwrite existing server.            │
│                                        [default: no-overwrite]               │
│ --config                         PATH  Config file path [default             │
│                                        $VIRTUAL_ENV/etc/certified].          │
│ --help                                 Show this message and exit.           │
╰──────────────────────────────────────────────────────────────────────────────╯
```

#### `certified add-client`

Directly add a known client to `known_clients/`.  Note that end-entity
(non-CA) self-signed certificates cannot be trusted directly by TLS — add a
CA certificate instead to trust all identities it signs.

```
 Usage: certified add-client [OPTIONS] NAME CRT [SCOPES]

 Add the client directly to your `known_clients` list.
 ...

╭─ Arguments ──────────────────────────────────────────────────────────────────╮
│ *    name        TEXT      Client's name. [required]                         │
│ *    crt         PATH      Client's certificate (PEM or b64-DER). [required] │
│      scopes      [SCOPES]  Whitespace-separated list of allowed scopes.      │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --overwrite    --no-overwrite          Overwrite existing client.            │
│                                        [default: no-overwrite]               │
│ --config                         PATH  Config file path [default             │
│                                        $VIRTUAL_ENV/etc/certified].          │
│ --help                                 Show this message and exit.           │
╰──────────────────────────────────────────────────────────────────────────────╯
```

#### `certified set-org`

Join an existing organization as a managed member: your self-signed CA is
discarded and replaced by the organization's signed certificate.  The org's
CA cert is added to both `known_servers/` and `known_clients/`.

Requires `--overwrite`.  **Destructive** — removes `CA.key`, `CA.crt`,
`id/`, and `CA/` from your config directory.

```
 Usage: certified set-org [OPTIONS] SIGNATURE

 Setup this instance as a member of the signing organization.

╭─ Arguments ──────────────────────────────────────────────────────────────────╮
│ *    signature      PATH  json signature response containing both            │
│                           "signed_cert" and "ca_cert". [required]            │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --overwrite    --no-overwrite          Overwrite existing authorization?     │
│                                        [default: no-overwrite]               │
│ --config                         PATH  Config file path [default             │
│                                        $VIRTUAL_ENV/etc/certified].          │
│ --help                                 Show this message and exit.           │
╰──────────────────────────────────────────────────────────────────────────────╯
```

### `message`

Send an mTLS-authenticated HTTP request from the command line.

```
 Usage: message [OPTIONS] URL [DATA]

 Send a json-message to an mTLS-authenticated HTTPS-REST-API.

╭─ Arguments ──────────────────────────────────────────────────────────────────╮
│ *    url      TEXT  Service's Resource URL [default: None] [required]        │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ json-formatted message body ────────────────────────────────────────────────╮
│   data      [DATA]  If present, the message is POST-ed to the URL.           │
│                     Example: '{"refs": [1,2], "query": "What is 2+2?"}'      │
│                     [default: None]                                          │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Options ────────────────────────────────────────────────────────────────────╮
│ -X          [GET|POST|PUT|DELETE|PATCH]  HTTP method  [default: None]        │
│ -v                                       show info-level logs                │
│ -vv                                      show debug-level logs               │
│ --config    PATH                         Config file path                    │
│ --json      PATH  POST contents of a JSON file                               │
│ --yaml      PATH  POST contents of a YAML file (converted to JSON)           │
│ --pp / --no-pp    Pretty-print JSON output  [default: no-pp]                 │
│ -H          TEXT  Header (curl-style, e.g. -H "X-Token: ABC")               │
│ --help            Show this message and exit.                                │
╰──────────────────────────────────────────────────────────────────────────────╯
```
