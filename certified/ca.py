""" A class for holding x509 signing certificates (CA)
    and leaf certificates (LeafCert)
"""

from typing import Optional, List, Callable
import datetime
import ssl

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.hazmat.primitives.asymmetric import (
    ed448,
    ed25519,
    ec
)

import biscuit_auth as bis

from .cert_base import FullCert

from .blob import PublicBlob, PrivateBlob, Blob, PWCallback
import certified.encode as encode
from .encode import cert_builder_common

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
                 get_pw: PWCallback = None) -> None:
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

    def sign_csr(self,
                 csr : x509.CertificateSigningRequest,
                 is_ca : bool = False) -> x509.Certificate:
        """ Sign the given CSR.

        Danger: Do not use this function unless you understand
                how the resulting certificate will be used.

        Args:
          csr: the certificate signing request
          is_ca: is the result a signing key?
                 If False, the result will be setup as an end-entity.
        """
        # Validate and rebuild name
        name_parts = []
        for n in csr.subject:
            # TODO: validate name here.
            name_parts.append(n)
        name = x509.Name( name_parts )

        # Validate and rebuild san
        my_san : Optional[x509.SubjectAlternativeName] = None
        try:
            san = csr.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            assert not is_ca, "non-CA must have SubjectAlternativeName."
            assert not san.critical, "SubjectAlternativeName must not be marked as critical."
            san_parts = []
            for p in san.value:
                # TODO: validate SAN parts here
                san_parts.append(p)
            my_san = x509.SubjectAlternativeName(san_parts)
        except x509.ExtensionNotFound:
            assert is_ca, "CSR should not have a SubjectAlternativeName field."

        # Validate key type.
        pubkey = csr.public_key()
        if not isinstance(pubkey, (ec.EllipticCurvePublicKey,
                                    ed25519.Ed25519PublicKey,
                                    ed448.Ed448PublicKey)):
            raise ValueError(f"Unsupported key type: {type(pubkey)}")

        path_length : Optional[int] = None
        if is_ca:
            assert self._path_length is not None
            path_length = self._path_length - 1
            if path_length < 0:
                raise ValueError("Unable to sign for a CA.")

        issuer = self._certificate.subject
        cert_builder = cert_builder_common(
            name, issuer, pubkey,
            self_signed = False
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length),
            critical=True,
        ).add_extension(
            CA_Usage if is_ca else EE_Usage,
            critical=True
        ).add_extension(
            encode.get_aki(self._certificate),
            critical=False
        )

        if not is_ca:
            cert_builder = cert_builder.add_extension(
                                EE_Extension,
                                critical=False)

        if my_san:
            cert_builder = cert_builder.add_extension(
                                    my_san, critical=False)

        return self.sign_cert( cert_builder )

    def sign_cert(self, builder) -> x509.Certificate:
        pubkey = self._certificate.public_key()
        return builder.sign(
            private_key = self._private_key,
            algorithm = encode.hash_for_pubkey(pubkey)
        )

    def sign_biscuit(self, builder : bis.BiscuitBuilder) -> bis.Biscuit:
        """Sign the biscuit being created.

        Danger: Do not sign biscuits unless you understand
                their potential use.

        Note: You can use to_base64 on the result to produce a token.

        Args:
          builder: the Biscuit just before signing

        Example:

        >>> from certified import encode
        >>> ca = CA.new(encode.person_name("Andrew Jackson"))
        >>> ca.sign_biscuit(BiscuitBuilder(
        >>>     "user({user_id}); check if time($time), $time < {expiration};",
        >>>     { 'user_id': '1234',
        >>>       'expiration': datetime.now(tz=timezone.utc) \
        >>>             + timedelta(days=1)
        >>>     }
        >>> ))
        """
        assert isinstance(self._private_key, ed25519.Ed25519PrivateKey)
        return builder.build(
            bis.PrivateKey.from_bytes(
                        self._private_key
                            .private_bytes_raw()
        ) )

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
        private_key = encode.PrivIface(key_type).generate() # type: ignore[union-attr]

        issuer = name           # A self-issued certificate
        aki: Optional[x509.AuthorityKeyIdentifier] = None
        if parent_cert is not None:
            parent_certificate = parent_cert._certificate
            issuer = parent_certificate.subject
            aki = encode.get_aki(parent_certificate)

        cert_builder = cert_builder_common(
            name, issuer, private_key.public_key(),
            self_signed = parent_cert is None
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length),
            critical=True,
        ).add_extension(
            CA_Usage,
            critical=True,
        )

        if aki:
            cert_builder = cert_builder.add_extension(aki, critical=False)
        if san:
            cert_builder = cert_builder.add_extension(san, critical=False)

        if parent_cert:
            certificate = parent_cert.sign_cert( cert_builder )
        else:
            certificate = cert_builder.sign( private_key,
                                  encode.PrivIface(key_type).hash_alg()
                        )
        return cls(PublicBlob(certificate).bytes(),
                   PrivateBlob(private_key).bytes())

    def create_child_ca(self, name : x509.Name,
                              san : x509.SubjectAlternativeName,
                              key_type: str = "ed25519") -> "CA":
        """Creates a child certificate authority

        Args:
          name: The x509 subject organization named by the certificate.
          san: Alternative names for the organization named by the certificate.
          key_type: type of key to generate

        Returns:
          CA: the newly-generated certificate authority

        Raises:
          ValueError: if the CA path length is 0
        """
        assert self._path_length is not None # although was validated before...
        if self._path_length == 0:
            raise ValueError("Can't create child CA: path length is 0")

        path_length = self._path_length - 1
        return CA.new(name, san,
                      path_length = path_length,
                      key_type = key_type,
                      parent_cert = self)

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

        key = encode.PrivIface(key_type).generate() # type: ignore[union-attr]

        aki = encode.get_aki(self._certificate)

        cert_builder = cert_builder_common(
                name,
                self._certificate.subject,
                key.public_key(),
                not_before=not_before,
                not_after=not_after,
        ).add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
        ).add_extension(
                aki,
                critical=False
        ).add_extension(
                san,
                # EE subjectAltName MUST NOT be critical when subject is nonempty
                critical=False,
        ).add_extension(
                EE_Usage,
                critical=True,
        ).add_extension(
                EE_Extension,
                critical=False,
        )

        cert = self.sign_cert(cert_builder)

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
            get_pw: PWCallback = None,
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
