# Code Issues Found During Docs Audit

Issues noticed in Python source during documentation work.
These are not doc issues — they are bugs or cleanups needed in the .py files themselves.

## Bugs

- **`encode.py:311`** — stray `print(n)` debug statement inside `get_urls()`.
  Should be removed before any release.

- **`layout.py:67`** — `CRTDir.__getitem__` uses bare `name + ".crt"` instead of
  `self.base / (name + ".crt")`, so the path is always relative to CWD rather
  than the configured directory.

- **`layout.py:97-112`** — `check_config`: the inner `gone()` helper calls `error()`
  multiple times (one for the "does not exist" case and a second unconditional call),
  then returns `(warnings, errors)` — but the callers in the loop don't use that
  return value and execution continues. The `notexist()` helper defined at line 114
  is never called (dead code, and also references free variable `p` before assignment).

- **`encode.py:329-331`** — unreachable code after `raise` in `get_aki()`:
  ```python
  except x509.ExtensionNotFound:
      raise
      # we want the pubkey to match, so skip this.
      return x509.AuthorityKeyIdentifier.from_issuer_public_key(...)  # never reached
  ```

## TODOs / Incomplete features

- **`cert.py:237-241`** — `Certified.lookup_public_key()`: FIXME comment says
  "use key serial numbers" — currently ignores `kid` and always returns the signer's key.
  Will silently break if multiple signing keys are ever present.

- **`ca.py:149`** — `CA.sign_biscuit()` asserts `isinstance(self._private_key, Ed25519PrivateKey)`,
  so it fails for Ed448 keys even though `CA.new()` accepts `key_type="ed448"`.

- **`certified.py:173`** — TODO comment: validate that `add_client` cert is actually
  a signing cert (self-signed end-entities can't be TLS clients).

- **`certified.py:215`** — TODO comment: validate that the `name` argument to
  `add_service` is a valid `host[:port]` (currently any string is accepted).

- **`certified.py:461`** — TODO comment: add `list` subcommands to show known clients
  and servers with their key types.

- **`models.py`** — `TrustedClient.cert` is typed `str` with no pydantic validator
  enforcing base64-DER format. A validator would catch misconfiguration early.

- **`cert.py:293-300`** — comment links to a 2012 CPython bug about needing a temp
  file for `load_cert_chain`. That bug is ancient — worth checking if it is still
  required in Python 3.10+.

## Minor / Style

- **`certified.py:456`** — `cert.serve(app, url, loki)` calls a sync wrapper that
  internally runs `asyncio.run(server.serve())`. The commented-out `asyncio.run()`
  just above it is dead code and should be removed.

- **`certified.py:401`** — commented-out `grant` command block should either be
  deleted or tracked in an issue. It references `actor_api` which is not a listed
  dependency.

- **`ca.py:126-155`** — docstring example for `sign_biscuit` is not valid Python
  (missing imports for `BiscuitBuilder`, `datetime`, `timezone`, `timedelta`).
