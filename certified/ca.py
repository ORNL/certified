""" A class for holding x509 signing certificates (CA)
    and leaf certificates (LeafCert)
"""

from typing import Optional, List, Callable
import datetime
import ssl

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from .cert_base import FullCert

from .blob import PublicBlob, PrivateBlob, Blob
import certified.encode as encode
from .encode import cert_builder_common

class CA(FullCert):
    """ CA-s are used only to sign other certificates.
        This design is required if one wants to use keys
        for either signing or key derivation, but not both.

        Note that while elliptic curve keys can be used for
        both signing and key exchange, this is
        bad [cryptographic practice](https://crypto.stackexchange.com/a/3313).
        Instead, users should generate separate signing and ECDH keys.
    """

    def __init__(self, cert_bytes: bytes, private_key_bytes: bytes,
                 get_pw: Optional[Callable[(), str]] = None) -> None:
        """Load a CA from an existing cert and private key.

        Args:
          cert_bytes: The bytes of the certificate in PEM format
          private_key_bytes: The bytes of the private key in PEM format
          get_pw: called to get the password to decrypt the key (if a password was set)
        """
        super().__init__(cert_bytes, private_key_bytes, get_pw)
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

        issuer = name           # A self-issued certificate
        sign_key = private_key  # self-signature.
        aki: Optional[x509.AuthorityKeyIdentifier] = None
        if parent_cert is not None:
            sign_key = parent_cert._private_key
            parent_certificate = parent_cert._certificate
            issuer = parent_certificate.subject
            aki = encode.get_aki(parent_certificate)

        cert_builder = cert_builder_common(
            name, issuer, private_key.public_key(),
            self_signed = parent_cert is None
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

        aki = encode.get_aki(self._certificate)

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
            PublicBlob(cert).bytes(),
            PrivateBlob(key).bytes()
        )

    def configure_trust(self, ctx: ssl.SSLContext) -> None:
        """Configure the given context object to trust certificates signed by
        this CA.

        Args:
          ctx: The SSL context to be modified.

        """
        ctx.load_verify_locations(cadata=self.cert_pem.bytes().decode("ascii"))


class LeafCert(FullCert):
    """A server or client certificate plus private key.

    Leaf certificates are used to authenticate parties in
    a TLS session.

    Attributes:
      cert_chain_pems (list of `Blob` objects): The zeroth entry in this list
          is the actual PEM-encoded certificate, and any entries after that
          are the rest of the certificate chain needed to reach the root CA.

      private_key_and_cert_chain_pem (`Blob`): A single `Blob` containing the
          concatenation of the PEM-encoded private key and the PEM-encoded
          cert chain.

    """

    def __init__(self,
            cert_bytes: bytes,
            private_key_bytes: bytes,
            get_pw: Optional[Callable[(), str]] = None,
            chain_to_ca: List[bytes] = []
    ) -> None:
        super().__init__(cert_bytes, private_key_bytes, get_pw)

        self.cert_chain_pems = [Blob(pem, is_secret=False) \
                                for pem in [cert_bytes] + chain_to_ca]
        self.private_key_and_cert_chain_pem = Blob(
            private_key_bytes + cert_bytes + b"".join(chain_to_ca),
            is_secret=True
        )

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
