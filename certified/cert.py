""" A class for holding x509 certificates for which we posess
    a private key.
"""

from typing import Optional, List, Callable

from cryptography import x509
#from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
)

from .blob import PublicBlob, PrivateBlob, Blob, Pstr
import certified.encode as encode
from .encode import CertificateIssuerPrivateKeyTypes

class FullCert:
    """ A full certificate contains both a certificate and private key.
    """
    _certificate: x509.Certificate
    _private_key: CertificateIssuerPrivateKeyTypes

    def __init__(self, cert_bytes: bytes, private_key_bytes: bytes,
                 get_pw: Optional[Callable[(), str]] = None) -> None:
        """Create from an existing cert and private key.

        Args:
          cert_bytes: The bytes of the certificate in PEM format
          private_key_bytes: The bytes of the private key in PEM format
          get_pw: get the password used to decrypt the key (if a password was set)
        """
        #self.parent_cert = None
        self._certificate = x509.load_pem_x509_certificate(cert_bytes)
        password : Optional[str] = None
        if get_pw:
            password = get_pw()
        self._private_key = load_pem_private_key(
                    private_key_bytes, password=password
        )

    @classmethod
    def load(cls, base : Pstr, get_pw = None):
        cert = Blob.read(str(base) + ".crt")
        key  = Blob.read(str(base) + ".key")
        assert key.is_secret, f"{base+'.key'} has compromised file permissions."
        return cls(cert.bytes(), key.bytes(), get_pw)
    
    def save(self, base : Pstr, overwrite = False):
        self.cert_pem.write(str(base) + ".crt")
        self._get_private_key().write(str(base) + ".key")

    @property
    def certificate(self) -> x509.Certificate:
        return self._certificate

    @property
    def cert_pem(self) -> PublicBlob:
        """`Blob`: The PEM-encoded certificate for this CA. Add this to your
        trust store to trust this CA."""
        return PublicBlob(self._certificate)

    def _get_private_key(self) -> PrivateBlob:
        """`PrivateBlob`: The PEM-encoded private key.
           You should avoid using this if possible.
        """
        return PrivateBlob(self._private_key)

    def __str__(self) -> str:
        return str(self.cert_pem)

    def create_csr(self) -> PublicBlob:
        """ Generate a CSR.
        """
        # parsing x509
        # crt.extensions.get_extension_for_class(
        #        x509.SubjectKeyIdentifier
        #    )
        #    sign_key = parent_cert._private_key
        #    parent_certificate = parent_cert._certificate
        #    issuer = parent_certificate.subject
        SAN = self._certificate.extensions.get_extension_for_class(
                SubjectAlternativeName
        )
        # TODO: read key type and call hash_for_key

        csr = x509.CertificateSigningRequestBuilder().subject_name(
            self._certificate.subject
        ).add_extension(
            SAN.value,
            critical=SAN.critical,
        ).sign(self._private_key) #, hashes.SHA256())
        return PublicBlob(csr)

    def revoke(self) -> None:
        # https://cryptography.io/en/latest/x509/reference/#x-509-certificate-revocation-list-builder
        raise RuntimeError("FIXME: Not implemented.")

