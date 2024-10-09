# Authorization Model

The `certified.fast` module provides some useful
FastAPI-specific functionality for authentication
and authorization.

The Critic (constructor) and BiscuitAuthz class, in particular,
provide a FastAPI dependency that gathers all relevant
information about a request, and then calls the
`biscuit_auth.Authorizor` to validate the client-provided
biscuit.

Note that the client must provide a header like,
"Biscuit: b64-encoded-biscuit" to successfully use
authz-annotated API functions.


## Annotating a function

To annotate a function, you have two options.

For functions requiring a specific scope, use
`Critic(app_name, pubkey_list)`.

    from certified.fast import Critic

    DevGroup = Critic(app_name, pubkey_list, "group:developers")

    @app.post("/fork")
    async def fork_code(commit:str, _: DevGroup):
        return f"forked {commit}"


For functions that don't require a specific scope,
but still want to validate the biscuit's internal
restrictions against the particular call (a very good idea),
use

    from FastAPI import Depends
    from certified.fast import BiscuitAuthz

    Authz = Depends(BiscuitAuthz(app_name, pubkey_list))

    @app.get("/")
    async def get_root(_: Authz):
        return ["answer"]


## Validation Models

When created, biscuits should contain user and role facts:
  - user({user who generated the token})
  - role({role the user wants to assume})
    * these are used for scope checking

It's OK if no roles are defined, but at least one (usually just one)
user must be defined.  All these definitions are "facts",
about the token so are effectively or-ed together.
This is because, as checks are run, they look for any
matching fact.  This idea comes from the prolog language.

When the authorizors mentioned above are run, they
make the following facts are available.

  - time({now}) -- where now is the current time 
  - client({id}) -- where id is the id of the client calling the API 
    * either `uid:<UserID from SAN>` (highest priority) 
    * or `cn:<common name from SAN>` (lowest priority) 
  - service({app\_name}) -- the name of this API service 
  - path({URL\_path}) -- path being accessed 
  - operation({method}) -- the HTTP method used (GET/PUT/etc.) 

Users can add restrictions to their tokens before passing
them to third-party services.

For example, to restrict a token so that it cannot
be passed around to make secondary calls by the receiving
server (usually a good idea),
a user (presumably named `my_username`), can add:

    check if client("id:my_username")

Alternately, to restrict a token so that it *can* be
re-used, but only by the `planner` microservice,
a user can add:

    check if client("cn:planner")

Or to restrict a token to only be used by "POST" or "PUT"
methods, a user can add:

    check if operation($op), ["POST", "PUT"].contains($op);

Lots of possibilities exist.  For more details, see
[BiscuitSec Attenuation Docs](https://doc.biscuitsec.org/recipes/per-request-attenuation).
