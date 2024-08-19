import pytest
from cryptography import x509
from certified import encode, CA

def test_csr():
    name = encode.org_name("Test Org.", "Section 7")
    #san = encode.SAN(hosts=["localhost"])
    ca = CA.new(name)

    csr = ca.create_csr()
    print(csr.subject)
    print(csr.public_key().public_bytes_raw())
    for n in csr.subject:
        print(n)

    #san = csr.extensions.get_extension_for_class(
    #    x509.SubjectAlternativeName
    #)
    #print(san.critical)
    #for n in san.value:
    #    print(n)

    with pytest.raises(AssertionError):
        print(ca.sign_csr(csr))

    name2 = encode.org_name("Test Org.", "Section 9")
    san = encode.SAN(hosts=["localhost"])
    csr2 = CA.new(name2, san).create_csr()
    csr3 = CA.new(name2).create_csr()
    print(ca.sign_csr(csr2))
    with pytest.raises(ValueError):
        print(ca.sign_csr(csr3, is_ca=True))

    ca = CA.new(name, path_length=1)
    with pytest.raises(AssertionError):
        print(ca.sign_csr(csr, is_ca=True))

    ca.sign_csr(csr3, is_ca=True)
