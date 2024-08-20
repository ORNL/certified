from typing import List

from cryptography import x509
from cryptography.x509 import DNSName
from cryptography.x509.verification import PolicyBuilder, Store

def by_chain(host : str, chain : List[x509.Certificate]) -> int:
    """ Verifies a chain of certificates,
        with the end-entity (with DNSName "host") at chain[0]
        and the root at chain[-1]

        Args:
          host: the DNSName of the 
          chain: the certificate chain
    """
    store = Store([chain[-1]])
    builder = PolicyBuilder().store(store)
    verifier = builder.build_server_verifier(DNSName(host))
    chain = verifier.verify(chain[0], chain[1:-1])
    return len(chain)

# https://m2crypto.readthedocs.io/en/latest/howto.migration.html#id8
from cryptography.x509 import load_pem_x509_certificate
def is_issued_by(ca, cert):
    # given a ca.pem and x509.pem, check that cert was issued by ca
    with open(ca, 'rb') as cacert_data:
        cacert = load_pem_x509_certificate(cacert_data.read())
    with open(cert, 'rb') as cert_data:
        cert = load_pem_x509_certificate(cert_data.read())
    return cert.verify_directly_issued_by(cacert)

# https://m2crypto.readthedocs.io/en/latest/howto.migration.html#id6
def show_cert(pem : str) -> None:
    # given an x509.pem, print its attributes
    with open(pem, 'rb') as cert_data:
        cert = load_pem_x509_certificate(cert_data.read())
    print(cert.issuer)
    print(cert.subject)
    print(cert.not_valid_before_utc)
    print(cert.not_valid_after_utc)

def contains_domain_validated(policies : x509.CertificatePolicies) -> bool:
    # example checking for this specific policy ID.
    return any(
        policy.policy_identifier.dotted_string == "2.23.140.1.2.1"
        for policy in policies
    )

if __name__ == "__main__":
    import sys
    show_cert(sys.argv[1])
