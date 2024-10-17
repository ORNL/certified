# Use DER-encoding with certificates
# so they become nice strings without newlines.
from typing import Union
import urllib.parse
import base64

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

# high-level routines
def b64_to_cert(inp: str, alt: bool = True) -> x509.Certificate:
    y = b64_to_der(inp, alt)
    return x509.load_der_x509_certificate(y)

def b64_to_csr(inp: str, alt: bool = True) -> x509.CertificateSigningRequest:
    y = b64_to_der(inp, alt)
    return x509.load_der_x509_csr(y)

def cert_to_b64(cert: Union[x509.Certificate,
                             x509.CertificateSigningRequest],
                alt: bool = True) -> str:
    return der_to_b64( cert.public_bytes(Encoding.DER) )

def pem_to_cert(inp: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(inp.encode('ascii'))

def pem_to_csr(inp: str) -> x509.CertificateSigningRequest:
    return x509.load_pem_x509_csr(inp.encode('ascii'))

def cert_to_pem(cert: Union[x509.Certificate,
                            x509.CertificateSigningRequest]) -> str:
    return cert.public_bytes(Encoding.PEM).decode('ascii')

# low-level routines (accounting for altchars)
def b64_to_der(inp: str, alt: bool = True) -> bytes:
    if alt:
        return base64.b64decode(inp, altchars=b'-_', validate=True)
    x = urllib.parse.unquote(inp)
    return base64.b64decode(x, validate=True)

def der_to_b64(inp: bytes, alt: bool = True) -> str:
    if alt:
        return base64.b64encode(inp, altchars=b'-_').decode('ascii')
    x = base64.b64encode(inp)
    return urllib.parse.quote_plus(x)

def serial_number(cert: x509.Certificate) -> str:
    """A canonical way to print a certificate's 160-bit
    serial number (as used by python/ssl)

    Returns its 40-byte hex representation.
    """
    inp = cert.serial_number.to_bytes(20, 'big')
    #return base64.b64encode(inp, altchars=b'-_').decode('ascii')
    return inp.hex()
