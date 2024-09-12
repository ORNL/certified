import pytest
from cryptography import x509
from certified import encode, CA, CertInfo

def test_csr() -> None:
    name = encode.org_name("Test Org.", "Section 7")
    #san = encode.SAN(hosts=["localhost"])
    ca = CA.new(name)

    csr = ca.create_csr()
    print(csr.subject)
    #print(csr.public_key().public_bytes_raw()) # only ed25519
    for n in csr.subject:
        print(n)

    #san = csr.extensions.get_extension_for_class(
    #    x509.SubjectAlternativeName
    #)
    #print(san.critical)
    #for n in san.value:
    #    print(n)

    info = CertInfo.load(csr)
    with pytest.raises(AssertionError):
        print(ca.issue_cert(info))

    name2 = encode.org_name("Test Org.", "Section 9")
    san = encode.SAN(hosts=["localhost"])
    csr2 = CA.new(name2, san).create_csr()
    info2 = CertInfo.load(csr2)
    csr3 = CA.new(name2).create_csr()
    info3 = CertInfo.load(csr3)

    info.is_ca = True
    info3.is_ca = True

    print(ca.issue_cert(info2))
    with pytest.raises(ValueError):
        print(ca.issue_cert(info3))

    ca = CA.new(name, path_length=1)
    with pytest.raises(AssertionError):
        print(ca.issue_cert(info))

    ca.issue_cert(info3)

    # self-signature
    with pytest.raises(AssertionError):
        ca.issue_cert(CertInfo(name, None, info3.pubkey, is_ca=True))
