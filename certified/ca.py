""" A class for holding x509 signing certificates (CA)
    and leaf certificates (LeafCert)
"""

from typing import Optional, List
import datetime
import ssl

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
#from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
)

from .blob import PublicBlob, PrivateBlob, Blob
import certified.encode as encode
from .encode import (
    CertificateIssuerPrivateKeyTypes,
    cert_builder_common,
)

class CA:
    """ A certificate plus a private key.

        CA-s are used only to sign other certificates.
        This design is required if one wants to use keys
        for either signing or key derivation, but not both.

        Note that while elliptic curve keys can be used for
        both signing and key exchange, this is
        bad [cryptographic practice](https://crypto.stackexchange.com/a/3313).
        Instead, users should generate separate signing and ECDH keys.
    """

    _certificate: x509.Certificate
    _private_key: CertificateIssuerPrivateKeyTypes

    def __init__(self, cert_bytes: bytes, private_key_bytes: bytes,
                 password: Optional[str] = None) -> None:
        """Load a CA from an existing cert and private key.

        Args:
          cert_bytes: The bytes of the certificate in PEM format
          private_key_bytes: The bytes of the private key in PEM format
          password: used to decrypt the key (if a password was set)
        """
        #self.parent_cert = None
        self._certificate = x509.load_pem_x509_certificate(cert_bytes)
        self._private_key = load_pem_private_key(
                    private_key_bytes, password=password
        )
        try:
            basic = self._certificate.extensions \
                        .get_extension_for_class(x509.BasicConstraints)
            assert basic.value.ca, "Loaded certificate is not a CA."
            self._path_length = basic.value.path_length
        except x509.ExtensionNotFound:
            raise ValueError("BasicConstraints not found.")
            self._path_length = None

    @classmethod
    def new(cls,
        name : x509.Name,
        san  : Optional[x509.SubjectAlternativeName] = None,
        path_length: int = 0,
        key_type : str = "ed25519",
        parent_cert: Optional["CA"] = None,
    ) -> "CA":
        """ Generate a new CA (root if parent_cert is None)

        Args:
          name: the subject of the key
          san:  the subject alternate name, including domains,
                emails, and uri-s
          path_length: max number of child CA-s allowed in a trust chain
          key_type: cryptographic algorithm for key use
          parent_cert: parent who will sign this CA (None = self-sign)
        """
        # Generate our key
        private_key = encode.PrivIface(key_type).generate()

        issuer = name
        sign_key = private_key
        aki: Optional[x509.AuthorityKeyIdentifier]
        if parent_cert is not None:
            sign_key = parent_cert._private_key
            parent_certificate = parent_cert._certificate
            issuer = parent_certificate.subject
            ski_ext = parent_certificate.extensions.get_extension_for_class(
                x509.SubjectKeyIdentifier
            )
            aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                ski_ext.value
            )
        else:
            aki = None

        cert_builder = cert_builder_common(
            name, issuer, private_key.public_key()
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length),
            critical=True,
        )
        if aki:
            cert_builder = cert_builder.add_extension(aki, critical=False)
        if san:
            cert_builder = cert_builder.add_extension(san, critical=False)

        certificate = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,  # OCSP
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,  # sign certs
                crl_sign=True,  # sign revocation lists
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).sign(
            private_key=sign_key,
            algorithm=encode.hash_for_key(key_type),
        )
        # TODO: lookup this algo for the sign_key type.
        return cls(PublicBlob(certificate).bytes(),
                   PrivateBlob(private_key).bytes())

    def __str__(self) -> str:
        return str(self.cert_pem)

    @property
    def certificate(self) -> x509.Certificate:
        return self._certificate

    @property
    def cert_pem(self) -> PublicBlob:
        """`Blob`: The PEM-encoded certificate for this CA. Add this to your
        trust store to trust this CA."""
        return PublicBlob(self._certificate)

    # this gets written to pytest error
    # messages if @property is used
    def get_private_key(self) -> PrivateBlob:
        """`Blob`: The PEM-encoded private key for this CA. Use this to sign
        other certificates from this CA."""
        return PrivateBlob(self._private_key)

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

    def create_child_ca(self, name : x509.Name,
                              key_type: str = "ed25519") -> "CA":
        """Creates a child certificate authority

        Args:
          name: the x509 organization named by the certificate
          key_type: type of key to generate

        Returns:
          CA: the newly-generated certificate authority

        Raises:
          ValueError: if the CA path length is 0
        """
        if self._path_length == 0:
            raise ValueError("Can't create child CA: path length is 0")

        path_length = self._path_length - 1
        return CA.new(parent_cert=self, path_length=path_length, key_type=key_type)

    def issue_cert(
        self,
        name: x509.Name,
        san: x509.SubjectAlternativeName,
        not_before: Optional[datetime.datetime] = None,
        not_after: Optional[datetime.datetime] = None,
        key_type: str = "ed25519"
    ) -> "LeafCert":
        """Issues a certificate. The certificate can be used for either
        servers or clients.

        emails, hosts, and uris ultimately end up as
        "Subject Alternative Names", which are what modern programs are
        supposed to use when checking identity.

        Args:
          name: x509 name (see `certified.encode.name`)

          san: subject alternate names -- see encode.SAN

          not_before: Set the validity start date (notBefore) of the certificate.
            This argument type is `datetime.datetime`.
            Defaults to now.

          not_after: Set the expiry date (notAfter) of the certificate. This
            argument type is `datetime.datetime`.
            Defaults to 365 days after `not_before`.

          key_type: Set the type of key that is used for the certificate.
            By default this is an ed25519 based key.

        Returns:
          LeafCert: the newly-generated certificate.

        """

        key = encode.PrivIface(key_type).generate()

        ski_ext = self._certificate.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        )
        aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            ski_ext.value
        )

        cert = (
            cert_builder_common(
                name,
                self._certificate.subject,
                key.public_key(),
                not_before=not_before,
                not_after=not_after,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(aki, critical=False)
            .add_extension(
                san,
                # EE subjectAltName MUST NOT be critical when subject is nonempty
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage(
                    [
                        ExtendedKeyUsageOID.CLIENT_AUTH,
                        ExtendedKeyUsageOID.SERVER_AUTH,
                        ExtendedKeyUsageOID.CODE_SIGNING,
                    ]
                ),
                # certificate won't verify if this is True (Certificate extension 2.5.29.37 has incorrect criticality)
                critical=False,
            )
            .sign(
                private_key=self._private_key,
                algorithm=encode.hash_for_key(key_type)
            )
        )

        return LeafCert(
            PrivateBlob(key).bytes(),
            PublicBlob(cert).bytes()
        )

    def configure_trust(self, ctx: ssl.SSLContext) -> None:
        """Configure the given context object to trust certificates signed by
        this CA.

        Args:
          ctx: The SSL context to be modified.

        """
        ctx.load_verify_locations(cadata=self.cert_pem.bytes().decode("ascii"))


class LeafCert:
    """A server or client certificate plus private key.

    Leaf certificates are used to authenticate parties in
    a TLS session.

    Attributes:
      private_key_pem (`PrivateBlob`): The PEM-encoded private key corresponding to
          this certificate.

      cert_chain_pems (list of `Blob` objects): The zeroth entry in this list
          is the actual PEM-encoded certificate, and any entries after that
          are the rest of the certificate chain needed to reach the root CA.

      private_key_and_cert_chain_pem (`Blob`): A single `Blob` containing the
          concatenation of the PEM-encoded private key and the PEM-encoded
          cert chain.

    """

    def __init__(
        self, private_key_pem: bytes, ee_cert_pem: bytes, chain_to_ca: List[bytes] = []
    ) -> None:
        self.private_key_pem = Blob(private_key_pem, True)
        self.cert_chain_pems = [Blob(pem, False) for pem in [ee_cert_pem] + chain_to_ca]
        self.private_key_and_cert_chain_pem = Blob(
            private_key_pem + ee_cert_pem + b"".join(chain_to_ca),
            True
        )
        self._certificate = x509.load_pem_x509_certificate(ee_cert_pem)

    @property
    def certificate(self) -> x509.Certificate:
        return self._certificate

    def configure_cert(self, ctx: ssl.SSLContext) -> None:
        """Configure the given context object to present this certificate.

        Args:
          ctx: The SSL context to be modified.
        """

        #with self.cert_chain_pems[0].tempfile() as crt:
        #    with self.private_key_pem.tempfile() as key:
        #        ctx.load_cert_chain(crt, keyfile=key)
        #return
        # Currently need a temporary file for this, see:
        #   https://bugs.python.org/issue16487
        with self.private_key_and_cert_chain_pem.tempfile() as path:
            try:
                ctx.load_cert_chain(path)
            except:
                #print("Path contents:")
                #print(self.private_key_and_cert_chain_pem.bytes().decode("ascii"))
                raise
