""" A class for holding x509 certificates for which we posess
    a private key.
"""
# Code in this file was originally derived from
# https://github.com/python-trio/trustme
#
# It was made available from that project under terms of the
# MIT license, reproduced here:
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

from typing import Optional, List

from cryptography import x509
#from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
)
# used only to name types below
from cryptography.hazmat.primitives.asymmetric import (
    ed448,
    ed25519,
    ec,
    rsa
)

from .blob import PublicBlob, PrivateBlob, Blob, Pstr, PWCallback
import certified.encode as encode
from .encode import CertificateIssuerPrivateKeyTypes, CertificatePublicKeyTypes
from .serial import cert_to_pem, serial_number

class FullCert:
    """ A full certificate contains both a certificate and private key.
    """
    _certificate: x509.Certificate
    _private_key: CertificateIssuerPrivateKeyTypes

    def __init__(self, cert_bytes: bytes, private_key_bytes: bytes,
                 get_pw: PWCallback = None) -> None:
        """Create from an existing cert and private key.

        Args:
          cert_bytes: The bytes of the certificate in PEM format
          private_key_bytes: The bytes of the private key in PEM format
          get_pw: get the password used to decrypt the key (if a password was set)
        """
        #self.parent_cert = None
        self._certificate = x509.load_pem_x509_certificate(cert_bytes)
        password : Optional[bytes] = None
        if get_pw:
            password = get_pw()
        pkey = load_pem_private_key(
                    private_key_bytes, password=password
        )
        assert isinstance(pkey, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey, rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)), f"Unusable key type: {type(pkey)}"
        self._private_key = pkey

    @classmethod
    def load(cls, base : Pstr, get_pw = None):
        cert = Blob.read(str(base) + ".crt")
        key  = Blob.read(str(base) + ".key")
        assert key.is_secret, f"{str(base)+'.key'} has compromised file permissions."
        return cls(cert.bytes(), key.bytes(), get_pw)
    
    def save(self, base : Pstr, overwrite = False):
        self.cert_pem.write(str(base) + ".crt")
        self._get_private_key().write(str(base) + ".key")

    @property
    def certificate(self) -> x509.Certificate:
        return self._certificate

    @property
    def pubkey(self) -> CertificatePublicKeyTypes:
        return self._certificate.public_key()

    @property
    def serial(self) -> str:
        return serial_number(self._certificate)

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

    def create_csr(self) -> x509.CertificateSigningRequest:
        """ Generate a CSR.
        """
        try:
            san = self._certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
        except x509.ExtensionNotFound:
            san = None
        pubkey = self._certificate.public_key()
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            self._certificate.subject
        )
        if san:
            csr = csr.add_extension(
                san.value,
                critical=san.critical,
            )
        return csr.sign(self._private_key, encode.hash_for_pubkey(pubkey))

    def revoke(self) -> None:
        # https://cryptography.io/en/latest/x509/reference/#x-509-certificate-revocation-list-builder
        raise RuntimeError("FIXME: Not implemented.")
