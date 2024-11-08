# Note: Library consumers may choose whether to import this
# package or not base on whether they have installed FastAPI.
#
# So... do not import this file from other parts of certified
# (except tests, where ImportError is handled).
#
from typing import Dict, Any, Annotated, Optional, Union, List, Protocol
from collections.abc import Callable
from datetime import datetime, timezone, timedelta

from fastapi import Request, Depends, HTTPException, Header
from .ca import CA

from biscuit_auth import (
        BiscuitBuilder,
        Authorizer,
        Biscuit,
        PublicKey,
        BiscuitValidationError,
        AuthorizationError,
        Fact,
        Policy,
)

def get_remote_addr(request: Request) -> Optional[str]:
    if request.client is None:
        return None
    return request.client.host

def get_peercert(request: Request) -> Dict[str,Any]:
    """FastAPI dependency for returning client cert. information

    Example return:
      {"subject":[[["commonName","Charles T. User"]]],
       "issuer":[[["commonName","Charles T. User"]],
                 [["pseudonym","Signing Certificate"]]],
       "version":3,
       "serialNumber":"03A2",
       "notBefore":"Sep 12 05:48:44 2024 GMT",
       "notAfter":"Sep 12 05:48:44 2025 GMT",
        "subjectAltName":[["email","hello@localhost"],
                         ["DNS","localhost"],
                         ["IP Address","127.0.0.1"]]
      }
    """

    if "transport" not in request.scope:
        return {}
    transport = request.scope["transport"]
    ans = transport.get_extra_info("peercert")
    if ans is None:
        return {}
    return ans

PeerCert = Annotated[Dict[str,Any], Depends(get_peercert)]

def name_from_peer(peer : Dict[str,Any]) -> str:
    name = None
    for nlist in peer["subject"]:
        for n in nlist:
            if n[0] == 'commonName':
                if name is None or name.startswith("cn:"):
                    name = f"cn:{n[1]}"
            elif n[0] == 'userID' or n[0] == 'userId':
                name = f"uid:{n[1]}"
    if name is None:
        raise KeyError("No usable name in peer certificate.")
    return name

def get_clientname(request: Request) -> str:
    """ A helper to return either (in priority order)

    1. uid:{userid of client}
    2. cn:{common name of client}
    3. addr:{ip addr. of client}
    """
    cert = get_peercert(request)
    try:
        return name_from_peer(cert)
    except KeyError:
        addr = get_remote_addr(request)
    if addr is None:
        raise HTTPException(status_code=401,
                            detail='Client identity is required.')
    return f"addr:{addr}"

ClientName = Annotated[str, Depends(get_clientname)]

class Baker:
    """This class provides a "get_token" method
    to prepare (bake) a token for a user.

    It should be used to create a "/token" endpoint as follows:

    >>> from certified.fast import Baker
    >>> cert = Certified()
    >>> baker = Baker(cert.signer())
    >>> app.post("/token")(baker.get_token)
    """
    def __init__(self, ca : CA):
        self.ca = ca

    def get_token(self,
                  client: ClientName,
                  hours: Optional[float] = 24.0):
        """ Returns a biscuit certifying the user identity
        and token lifetime.

        Applications should supply this as their "/token" endpoint
        """
        builder : BiscuitBuilder
        if hours is None:
            builder = BiscuitBuilder(
                "user({client});", {'client': client})
        else:
            builder = BiscuitBuilder(
                "user({client});"
                " check if time($time), $time < {expiration};",
                { 'client': client,
                  'expiration': datetime.now(tz=timezone.utc)
                                 + timedelta(hours=hours)
                })
        biscuit = self.ca.sign_biscuit(builder)
        token = biscuit.to_base64()
        return token
        #return {"access_token": token, "token_type": "bearer"}

class AuthMethod(Protocol):
    def __call__(self, auth: Authorizer, revocation_ids: List[str]) -> bool:
        return False

def run_authz(auth: Authorizer, revocation_ids: List[str]) -> bool:
    """ Default is to call authorizer.authorize()
        and ignore revocation id-s.

        This will ensure all the biscuit's (client-controlled)
        checks pass, but not enforce any specific security
        requirements from the server's side other than
        that the certificate names a user.
    """
    #auth.add_policy(Policy('allow if true'))
    auth.add_policy(Policy('allow if user($u)'))
    try:
        auth.authorize()
    except AuthorizationError:
        return False
    return True

class BiscuitAuthz:
    """For additional help on using biscuit attributes
    and checks, see docs/authz.md

    Instances of this class are callables which will
    check (critique) a token for a particular purpose.

    It may be used directly as follows:
    >>> from biscuit_auth import PublicKey
    >>> from certified.fast import BiscuitAuthz
    >>> app_name = __name__
    >>> pubkey = lambda i: PublicKey.from_bytes( "authorizer pubkey" )
    >>> DefaultAuthz = Annotated[bool, BiscuitAuthz(app_name, pubkey)]
    >>> async def get_info(info: str, authz: DefaultAuthz):
    >>>    # authz is always True here
    >>>    return info

    This will allow use of the get_info endpoint only
    if the caller provides a valid biscuit that passes all
    its own internal restrictions.

    Note this is a parameterized dependency.
    See https://fastapi.tiangolo.com/advanced/advanced-dependencies
    """
    app: str
    pubkeys: Callable[[int], PublicKey]
    auth_method: AuthMethod

    def __init__(self,
                 app: str,
                 pubkeys: Union[List[PublicKey],
                                Callable[[int], PublicKey]],
                 auth_method: AuthMethod = run_authz
                ) -> None:
        self.app = app
        
        if isinstance(pubkeys, list):
            self.pubkeys = lambda i: pubkeys[i]
        else:
            self.pubkeys = pubkeys
        self.auth_method = auth_method

    def lookup_public_key(self, kid : Optional[int] = None
                         ) -> PublicKey:
        ans = self.pubkeys(kid or 0)
        return ans

    def biscuit(self, token : str) -> Biscuit:
        # may throw BiscuitValidationError
        return Biscuit.from_base64(token, self.lookup_public_key)

    def __call__(self,
                 request: Request,
                 biscuit: Annotated[Union[str,None],Header()] = None
                ) -> bool:
        if biscuit is None:
            raise HTTPException(status_code=401, detail='Required header "Biscuit: urlsafe-b64-encoded-value" not found.')

        try:
            bis = self.biscuit(biscuit)
        except BiscuitValidationError:
            raise HTTPException(status_code=401, detail='Required header "Biscuit: urlsafe-b64-encoded-value" invalid format.')

        cert = get_peercert(request)
        client = get_clientname(request)

        authorizer = Authorizer(
                    "time({now});"
                    " client({client});"
                    " service({srv});"
                    " path({path});"
                    " operation({operation});",
                    {'now': datetime.now(tz = timezone.utc),
                     'client': client,
                     'srv': self.app,
                     'path': request.url.path,
                     'operation': request.method
                    })
        if 'serialNumber' in cert:
            authorizer.add_fact(Fact('client_serial({no})',
                                {'no': cert['serialNumber']}))
        authorizer.add_token(bis)
        if not self.auth_method(authorizer, bis.revocation_ids):
            raise HTTPException(status_code=403, detail='Forbidden')
        return True

def Critic(app: str,
           pubkeys: Union[List[PublicKey],
                          Callable[[int], PublicKey]]
          ) -> Callable[[AuthMethod], bool]:
    """Returns an Authorizer, which can be called
    with a custom authorizer to add authentication to your
    FastAPI endpoint.

    >>> from biscuit_auth import PublicKey
    >>> from certified.fast import Critic, run_authz
    >>> pubkey = [PublicKey.from_bytes(b"authorizer pubkey1"), PublicKey.from_bytes(b"authorizer pubkey2")]
    >>> def custom(authorizer, revoke_ids):
    >>>    authorizer.add_code()
    >>>    return run_authz(authorizer)
    >>> Authz = Critic("frontend app name", pubkeys)
    >>> async def post_config(info: str, authz: Annotated[bool, Authz(custom)):
    >>>    # authz is always True here
    >>>    set_info(info)

    Since `Authz("admin:write")` has created a dependency
    (of type BiscuitAuthz(app, pubkeys, "admin:write")),
    that dependency can gather data from:
     - the client certificate, providing client({id})
     - the URL accessed, providing path({path}) and operation({method})
     - the call header, where a "Biscuit: b64_encoded_biscuit" is
       required

    It then throws an HTTP Unauthorized/401 if a biscuit is missing,
    Forbidden/403 if the biscuit auth fails, or else returns True otherwise.
    """
    return lambda azfn: Depends(BiscuitAuthz(app, pubkeys, azfn))
