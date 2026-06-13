"""
Tests for x509 ↔ biscuit key translation (encode.cert_*_to_biscuit_*).

test_x509_to_biscuit: for each supported key type, generate an x509 CA,
sign a biscuit with its private key, then verify the token using the
translated public key.  This is the full round-trip that certifies the
translation functions are interoperable.

Unsupported key types (ed448, secp384r1, secp521r1, secp256k1) are
verified to return None from the translation functions.
"""
from datetime import datetime, timedelta, timezone

import pytest
from biscuit_auth import BiscuitBuilder, UnverifiedBiscuit, AuthorizerBuilder

from certified import encode, CA
from certified.encode import (
    cert_key_to_biscuit_alg,
    cert_privkey_to_biscuit_bytes,
    cert_pubkey_to_biscuit_bytes,
)
import biscuit_auth as bis

# ── parametrize ───────────────────────────────────────────────────────────────

SUPPORTED = ["ed25519", "secp256r1"]
UNSUPPORTED = ["ed448", "secp384r1", "secp521r1", "secp256k1"]


# ── helpers ───────────────────────────────────────────────────────────────────

def make_ca(key_type: str) -> CA:
    name = encode.org_name("Test Org", "Testing", pseudonym="Signing Certificate")
    return CA.new(name, key_type=key_type)


def sign_and_verify(ca: CA) -> None:
    """Sign a biscuit with the CA private key; verify with the translated pubkey."""
    priv = ca._private_key
    pub  = ca.pubkey

    alg      = cert_key_to_biscuit_alg(priv)
    priv_raw = cert_privkey_to_biscuit_bytes(priv)
    pub_raw  = cert_pubkey_to_biscuit_bytes(pub)
    assert alg is not None and priv_raw is not None and pub_raw is not None

    # Sign
    biscuit_priv = bis.PrivateKey.from_bytes(priv_raw, alg=alg)   # type: ignore[call-arg]
    token = BiscuitBuilder(
        'user({uid}); check if time($t), $t < {exp};',
        {'uid': 'test-user',
         'exp': datetime.now(tz=timezone.utc) + timedelta(hours=1)},
    ).build(biscuit_priv).to_base64()

    # Verify using the translated public key
    biscuit_pub = bis.PublicKey.from_bytes(pub_raw, alg=alg)       # type: ignore[call-arg]
    verified = UnverifiedBiscuit.from_base64(token).verify(biscuit_pub)

    authorizer = AuthorizerBuilder(
        'time({now}); allow if user($u);',
        {'now': datetime.now(tz=timezone.utc)},
    ).build(verified)
    authorizer.authorize()

    facts = authorizer.query(bis.Rule('user($u) <- user($u)'))
    assert len(facts) == 1
    assert tuple(facts[0].terms) == ('test-user',)


# ── tests ─────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("key_type", [
    pytest.param("ed25519",   id="ed25519"),
    pytest.param("secp256r1", id="secp256r1-P256"),
])
def test_x509_to_biscuit(key_type: str) -> None:
    """Full x509 CA → biscuit sign → biscuit verify round-trip."""
    ca = make_ca(key_type)
    sign_and_verify(ca)


@pytest.mark.parametrize("key_type", [
    pytest.param("ed448",     id="ed448"),
    pytest.param("secp384r1", id="secp384r1-P384"),
    pytest.param("secp521r1", id="secp521r1-P521"),
    pytest.param("secp256k1", id="secp256k1"),
])
def test_unsupported_returns_none(key_type: str) -> None:
    """Translation functions return None for key types biscuit_auth doesn't support."""
    ca = make_ca(key_type)
    assert cert_key_to_biscuit_alg(ca._private_key) is None
    assert cert_privkey_to_biscuit_bytes(ca._private_key) is None
    assert cert_pubkey_to_biscuit_bytes(ca.pubkey) is None
