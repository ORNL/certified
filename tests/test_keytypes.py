from certified import encode

# surprisingly difficult.
def test_pkey():
    for keytype in ["ed25519", "ed448", "secp256r1",
                    "secp384r1", "secp521r1", "secp256k1"]:
        print(keytype)
        priv_if = encode.PrivIface(keytype)

        key = priv_if.generate()
        pkey = key.public_key()

        assert priv_if.hash_alg().__class__ \
                    == encode.hash_for_pubkey(pkey).__class__
