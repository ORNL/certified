from typing import Annotated
from datetime import datetime, timedelta, timezone

import pytest
from biscuit_auth import BiscuitBuilder, BlockBuilder, UnverifiedBiscuit
from fastapi import Depends, HTTPException

from certified import encode, CA, Certified
from certified.fast import Baker, BiscuitAuthz, Critic, name_from_peer

def test_sign() -> None:
    ca = CA.new(encode.person_name("Andrew Jackson"))
    builder = BiscuitBuilder(
        """user({user_id});
           check if time($time), $time < {expiration};
        """,
        { 'user_id': '1234',
          'expiration': datetime.now(tz=timezone.utc) \
                + timedelta(days=1)
        }
    )
    #builder.set_root_key_id(0)
    sgn = ca.sign_biscuit(builder)
    print(sgn)

@pytest.fixture
def cert(tmp_path) -> Certified:
    name = encode.org_name("ACME Widgets", "R&D")
    san  = encode.SAN(hosts=["localhost", "127.0.0.1", "::1"])
    return Certified.new(name, san, tmp_path)

def test_bake_crit(cert) -> None:
    Authz = Annotated[bool, Depends(BiscuitAuthz("test_fast:cert",
                                             cert.lookup_public_key))]

    baker = Baker( cert.signer() )
    # example return from get_peercert
    peer = {"subject":[[["commonName","player1"]]]}
    tok = baker.get_token(name_from_peer(peer), None)
    print(tok)
    print(cert.lookup_public_key(0))

    Authz2 = Critic("test_fast:cert", cert.lookup_public_key)
    authz = BiscuitAuthz("test_fast:cert", cert.lookup_public_key)

    peer2 = name_from_peer({"subject":[[["commonName","player2"]]]})
    class Req: # fake request object
        def __init__(self, method, path):
            self.method = method
            self.url = self
            self.path = path
    # cn:player2 uses a token issued to cn:player1 to GET /path
    ok = authz(peer2, Req("GET", "/path"), tok) # type: ignore[arg-type]
    assert ok

    tok2 = UnverifiedBiscuit.from_base64(tok) \
            .append(BlockBuilder(
                'check if client("cn:player2");'
                ' check if operation({op})',
                { 'op': 'GET'})) \
            .verify(cert.lookup_public_key) \
            .to_base64()
    # cn:player2 uses a token issued to cn:player1 to GET /path
    # and only cn:player2 is allowed to use the token
    print(peer2)
    ok = authz(peer2, Req("GET", "/path"), tok2) # type: ignore[arg-type]

    tok3 = UnverifiedBiscuit.from_base64(tok) \
            .append(BlockBuilder(
                'check if client("cn:player1");'
                ' check if operation({op})',
                { 'op': 'GET'})) \
            .verify(cert.lookup_public_key) \
            .to_base64()
    # cn:player2 uses a token issued to cn:player1 to GET /path
    # and only cn:player1 is allowed to use the token
    with pytest.raises(HTTPException):
        ok = authz(peer2, Req("GET", "/path"), tok3) # type: ignore[arg-type]

    peer3 = name_from_peer({"subject":[[["commonName","Prof. X"],
                                        ["userId","xyz"]]]})
    assert peer3 == 'uid:xyz'
