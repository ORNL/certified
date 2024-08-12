from typing import List

from cryptography import x509
from cryptography.x509 import DNSName
from cryptography.x509.verification import PolicyBuilder, Store

def by_chain(host : str, *chain : x509) -> int:
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

