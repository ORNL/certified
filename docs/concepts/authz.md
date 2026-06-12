# Authorization Model

!!! tip "Two-layer security model"
    `certified` separates **authentication** (x509 mTLS — *who are you?*) from
    **authorisation** (biscuit token + scope file — *what may you do?*).
    A valid certificate proves identity; it grants nothing by itself.
    See [Key Management](keys.md) for the authentication layer.

## What a certificate grants

A verified client certificate establishes identity and grants the default
permissions available to all users of that organisation — essentially,
single-user access to whichever services have added that certificate (or its
signing CA) to their `known_clients/` directory.

Biscuit tokens are for everything beyond that baseline:

| Use case | Mechanism |
|---|---|
| Delegated authority (act on my behalf) | Biscuit issued by the delegating user |
| Special access roles (admin, auditor…) | Biscuit with role fact, checked server-side |
| Dynamic restrictions (time-limited, path-limited…) | Attenuation blocks added to the biscuit |
| Cross-service calls (service A calls service B on your behalf) | Attenuated biscuit forwarded in `Biscuit:` header |

## How authorisation works

`certified` does **not** automatically enforce the `.scope` files.  The scope
files are metadata you maintain; actual enforcement is your responsibility.
The `certified.fast` module gives you the building blocks:

- [`Baker`](../reference/fast.md#baker) — issues biscuit tokens signed by your CA key
- [`BiscuitAuthz`](../reference/fast.md#biscuitauthz) — FastAPI dependency that validates a biscuit in the `Biscuit:` header
- [`Critic`](../reference/fast.md#critic) — `BiscuitAuthz` variant that also requires a specific scope

You wire these into your FastAPI app as dependencies and write your own
authoriser logic using the biscuit datalog policy language.

## Annotating a function

For functions requiring a specific scope:

```python
from certified.fast import Critic

DevGroup = Critic(app_name, pubkey_list, "group:developers")

@app.post("/fork")
async def fork_code(commit: str, _: DevGroup):
    return f"forked {commit}"
```

For functions that validate biscuit restrictions without requiring a specific
scope:

```python
from fastapi import Depends
from certified.fast import BiscuitAuthz

Authz = Depends(BiscuitAuthz(app_name, pubkey_list))

@app.get("/")
async def get_root(_: Authz):
    return ["answer"]
```

## Validation model

Biscuits should contain `user` and `role` facts:

```
user("alice@org1.example");
role("developers");
```

When the authorizors above run, they inject the following facts into the
datalog evaluation:

| Fact | Value |
|---|---|
| `time({now})` | current UTC time |
| `client({id})` | `uid:<UserID from SAN>` or `cn:<common name>` |
| `service({app_name})` | the name of this API service |
| `path({url_path})` | URL path being accessed |
| `operation({method})` | HTTP method (GET, POST, …) |

## Token attenuation examples

Users can narrow a token before passing it to a third-party service.

Prevent re-delegation (caller must be the original user):
```
check if client("uid:alice@org1.example");
```

Allow re-use only by a specific downstream service:
```
check if client("cn:planner");
```

Restrict to write methods only:
```
check if operation($op), ["POST", "PUT", "PATCH"].contains($op);
```

For more, see the [BiscuitSec Attenuation Docs](https://doc.biscuitsec.org/recipes/per-request-attenuation).
