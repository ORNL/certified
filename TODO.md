# TODO

Cross-reference of code issues found during docs audit and open roadmap items.

---

## Bugs (found during docs audit)

- **`encode.py:311`** — stray `print(n)` debug statement inside `get_urls()`. Remove before release.

- **`layout.py:67`** — `CRTDir.__getitem__` uses bare `name + ".crt"` instead of
  `self.base / (name + ".crt")`, so the returned path is always relative to CWD rather
  than the configured directory.

- **`layout.py:97-112`** — `check_config`: the inner `gone()` helper calls `error()`
  multiple times then returns `(warnings, errors)` that callers never use; execution
  continues past a detected error. The `notexist()` helper at line 114 is dead code and
  references `p` before assignment.

- **`encode.py:329-331`** — unreachable code after `raise` in `get_aki()`:
  the `return x509.AuthorityKeyIdentifier.from_issuer_public_key(...)` after `raise` is
  never executed but the comment above it suggests it was intentional.

---

## Code TODOs / incomplete features

- **`cert.py:237`** — `lookup_public_key()` FIXME: ignores `kid` and always returns the
  signer's key. Will silently break when multiple signing keys are present. Fix: index by
  key serial number from the biscuit token root block.

- **`certified.py:173`** — TODO: validate that the cert passed to `add_client` is a CA
  cert (self-signed end-entities cannot be TLS clients; currently any cert is accepted).

- **`certified.py:215`** — TODO: validate that the `name` argument to `add_service` is a
  valid `host[:port]` string. Currently any string is accepted silently.

- **`certified.py:461`** — TODO: add `list` subcommands to show known clients and servers
  with their key types and fingerprints. (Related roadmap item: v1.2.0 "interface for
  showing configuration contents".)

- **`models.py`** — `TrustedClient.cert` is typed `str` with no validator enforcing
  base64-DER format. A pydantic validator would catch misconfigured YAML early.

- **`cert.py:293-300`** — comment cites a 2012 CPython bug requiring a temp file for
  `load_cert_chain`. Worth checking whether this workaround is still needed in Python 3.10+.

- **`ca.py:126-155`** — docstring example for `sign_biscuit` is not valid Python: missing
  imports for `BiscuitBuilder`, `datetime`, `timezone`, `timedelta`. Fix or replace with a
  pointer to `tests/test_biscuit_bridge.py`.

---

## Minor / style

- **`certified.py:456`** — dead `asyncio.run()` call commented out just above the sync
  wrapper that internally calls `asyncio.run(server.serve())`. Remove the dead line.

- **`certified.py:401`** — commented-out `grant` command block references `actor_api`
  which is not a dependency. Delete or open a tracked issue.

---

## Roadmap (from README)

### v1.2.0
- [ ] CI and better test coverage (cross_chain.py and test_biscuit_bridge.py are a start)
- [ ] Better documentation for `known_servers` config format
- [ ] Interface for showing configuration contents (`certified list clients`, `certified list services`)

### v1.2.1
- [ ] Warn if `id.crt` SAN does not contain the service's hostname (SSL will fail at
  connect time with a confusing error; catching it at `certified init` or `add-intro` time
  is much friendlier)

### v1.3.0
- [ ] More helpful error messages throughout (especially SSL handshake failures — surface
  which cert was rejected and why)
- [ ] CLI interface for biscuit creation and validation (`certified biscuit issue`,
  `certified biscuit verify`)
- [ ] Demo presentations / lessons learned docs

### v1.4.0
- [ ] Add certificate serial numbers — needed by `lookup_public_key` to key-index biscuit
  root blocks correctly (see `cert.py:237` FIXME above)
- [ ] Log all certificates signed and revoked; evaluate CSR workflow
- [ ] Support nng TLS sockets
- [ ] Support gRPC library

### v1.5.0
- [ ] Key rotation features and docs

---

## Already resolved (this session)

- `ca.py:149` — hard-coded `Ed25519` assertion in `sign_biscuit()` replaced with
  `cert_key_to_biscuit_alg()` / `cert_privkey_to_biscuit_bytes()` (authz branch).
- `cert.py` — `lookup_public_key()` updated to use translation functions for secp256r1
  support (authz branch).
- All cert-level scope references removed from models, cert.py, certified.py, docs (authz branch).
