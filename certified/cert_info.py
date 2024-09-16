from typing import Optional, List, Union
import datetime

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.hazmat.primitives.asymmetric import (
    ed448,
    ed25519,
    ec
)
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificatePublicKeyTypes,
)

from .encode import get_path_length, get_is_ca, cert_builder_common, get_aki

CA_Usage = x509.KeyUsage(
    digital_signature=True,  # OCSP
    content_commitment=False,
    key_encipherment=False,
    data_encipherment=False,
    key_agreement=False,
    key_cert_sign=True,  # sign certs
    crl_sign=True,  # sign revocation lists
    encipher_only=False,
    decipher_only=False,
)
EE_Usage = x509.KeyUsage(
    digital_signature=True,
    content_commitment=False,
    key_encipherment=True,
    data_encipherment=False,
    key_agreement=False,
    key_cert_sign=False,
    crl_sign=False,
    encipher_only=False,
    decipher_only=False,
)

EE_Extension = x509.ExtendedKeyUsage( [
    ExtendedKeyUsageOID.CLIENT_AUTH,
    ExtendedKeyUsageOID.SERVER_AUTH,
    ExtendedKeyUsageOID.CODE_SIGNING,
] )

class CertInfo:
    """Hold information from a certificate in a
    more accessible data structure:

    subject: the certificate subject's Name (see `certified.encode.person_name`)
    san:     subject alternate name (see `certified.encode.SAN`)
    pubkey:  public key
    is_ca:   whether this certificate is for digital signatures
    """

    subject : List[x509.NameAttribute]
    san     : List[x509.GeneralName]
    pubkey  : CertificatePublicKeyTypes
    is_ca   : bool

    def __init__(self, subject : x509.Name,
                       san : Optional[x509.SubjectAlternativeName],
                       pubkey : CertificatePublicKeyTypes,
                       is_ca : bool = False) -> None:
        self.subject = list(subject)
        if san:
            self.san = list(san)
        else:
            self.san = []
        self.pubkey = pubkey
        self.is_ca = is_ca

    @classmethod
    def load(cls, csr : Union[x509.CertificateSigningRequest,
                              x509.Certificate]
            ):
        if isinstance(csr, x509.CertificateSigningRequest):
            assert csr.is_signature_valid, "CSR has invalid signature!"
        is_ca = get_is_ca(csr)

        san : Optional[x509.SubjectAlternativeName] = None
        try:
            sane = csr.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            san = sane.value
        except x509.ExtensionNotFound:
            pass

        # Validate key type.
        pubkey = csr.public_key()
        if not isinstance(pubkey, (ec.EllipticCurvePublicKey,
                                    ed25519.Ed25519PublicKey,
                                    ed448.Ed448PublicKey)):
            raise ValueError(f"Unsupported key type: {type(pubkey)}")
    
        return cls(csr.subject, san, pubkey, is_ca)

    def get_name(self) -> x509.Name:
        assert len(self.subject) > 0, "SubjectName must be non-empty."
        return x509.Name( self.subject )

    def get_san(self) -> Optional[x509.SubjectAlternativeName]:
        #if not (self.is_ca or len(self.subject) == 0):
        #    assert len(self.san) > 0, "SubjectAltName must be non-empty for non-CA."
        if len(self.san) == 0:
            return None
        return x509.SubjectAlternativeName(self.san)
    
    def has_basic_subject(self):
        # TODO: check existence of some basic name parts
        return len(self.subject) > 0

    def has_basic_san(self):
        return len(self.san) > 0

    def build(self,
              issuer : Optional[x509.Certificate],
              not_before: Optional[datetime.datetime] = None,
              not_after: Optional[datetime.datetime] = None,
              path_length: Optional[int] = None
             ) -> x509.CertificateBuilder:
        """Creates a certificate builder waiting for a signature.

        Args:
          not_before: Set the validity start date (notBefore) of the certificate.
            This argument type is `datetime.datetime`.
            Defaults to now.

          not_after: Set the expiry date (notAfter) of the certificate. This
            argument type is `datetime.datetime`.
            Defaults to 365 days after `not_before`.

          key_type: Set the type of key that is used for the certificate.
            By default this is an ed25519 based key.

        Returns:
          cryptography.x509.CertificateBuilder

        """
        
        if issuer is None: # self-signed
            issuer_name = self.get_name()
        else:
            issuer_name = issuer.subject
            if self.is_ca:
                plen = get_path_length(issuer)
                assert plen is not None, "Issuer has no path length."
                path_length = min(path_length or 0, plen - 1)
                if path_length < 0:
                    raise ValueError("Unable to sign for a CA (insufficient path length).")
            if not_before:
                not_before = max(not_before, issuer.not_valid_before_utc)
            if not_after:
                not_after = min(not_after, issuer.not_valid_after_utc)
            # FIXME: set these attributes to default values if None

        cert_builder = cert_builder_common(
            self.get_name(), issuer_name, self.pubkey,
            not_before = not_before,
            not_after = not_after,
            self_signed = issuer is None
        ).add_extension(
            x509.BasicConstraints(ca=self.is_ca,
                                  path_length=path_length),
            critical=True,
        ).add_extension(
            CA_Usage if self.is_ca else EE_Usage,
            critical=True
        )
        if not self.is_ca:
            cert_builder = cert_builder.add_extension(
                                EE_Extension,
                                critical = False)

        if issuer is not None:
            cert_builder = cert_builder.add_extension(
                get_aki(issuer),
                critical=False
            )
        san = self.get_san()
        if san:
            # Mark SAN critical iff Name is empty
            cert_builder = cert_builder.add_extension(
                    san,
                    critical = len(self.subject) == 0 )
        return cert_builder
