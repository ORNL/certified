""" Functionality for generating certificates.
"""

from typing import Optional, List
from enum import Enum
import datetime
import ipaddress
import ssl
import idna

from cryptography.hazmat.primitives.asymmetric import (
    ed448, 
    ed25519
)
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificatePublicKeyTypes,
    CertificateIssuerPrivateKeyTypes
)
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from cryptography import x509
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)

from blob import *

def PrivIface(keytype) -> CertificateIssuerPrivateKeyTypes:
    if keytype == "ed25519":
        return ed25519.Ed25519PrivateKey
    elif keytype == "ed448":
        return ed448.Ed448PrivateKey

def PubIface(keytype) -> CertificatePublicKeyTypes:
    if keytype == "ed25519":
        return ed25519.Ed25519PublicKey
    elif keytype == "ed448":
        return ed448.Ed448PublicKey


def _cert_builder_common(
        subject: x509.Name,
        issuer: x509.Name,
        public_key: CertificatePublicKeyTypes,
        not_before: Optional[datetime.datetime] = None,
        not_after: Optional[datetime.datetime] = None,
    ) -> x509.CertificateBuilder:
    not_before = not_before if not_before else datetime.datetime.now(datetime.timezone.utc)
    # default valid for ~1 years
    not_after = not_after if not_after else (
            not_before + datetime.timedelta(days=365)
    )
    return (
        x509.CertificateBuilder()
            . subject_name(subject)
            . issuer_name(issuer)
            . public_key(public_key)
            . not_valid_before(not_before)
            . not_valid_after(not_after)
            . serial_number(x509.random_serial_number())
            . add_extension(
                x509.SubjectKeyIdentifier.from_public_key(public_key),
                critical=False,
            )
    )

def encode_name(
    organization_name: str,
    name: str,
    common_name: Optional[str] = None,
) -> x509.Name:
    """
    Build and return an x509.Name.

    Args:
          common_name: Sets the "Common Name" of the certificate. This is a
            legacy field that used to be used to check identity. It's an
            arbitrary string with poorly-defined semantics, so `modern
            programs are supposed to ignore it
            <https://developers.google.com/web/updates/2017/03/chrome-58-deprecations#remove_support_for_commonname_matching_in_certificates>`__.
            But it might be useful if you need to test how your software
            handles legacy or buggy certificates.

          organization_name: Sets the "Organization Name" (O) attribute on the
            certificate.

          organization_unit_name: Sets the "Organization Unit Name" (OU)
            attribute on the certificate.
    """

    name_pieces = []
    location = False # FIXME
    if location:
        name_pieces += [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        ]
    name_pieces += [
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, name),
    ]
    if common_name is not None:
        name_pieces.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
    return x509.Name(name_pieces)

def _encode_host(host):
    # Have to try ip_address first, because ip_network("127.0.0.1") is
    # interpreted as being the network 127.0.0.1/32. Which I guess would be
    # fine, actually, but why risk it.
    try:
        return x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        try:
            return x509.IPAddress(ipaddress.ip_network(host))
        except ValueError:
            pass

    # Encode to an A-label, like cryptography wants
    if host.startswith("*."):
        alabel_bytes = b"*." + idna.encode(host[2:], uts46=True)
    else:
        alabel_bytes = idna.encode(host, uts46=True)
    # Then back to text, which is mandatory on cryptography 2.0 and earlier,
    # and may or may not be deprecated in cryptography 2.1.
    alabel = alabel_bytes.decode("ascii")
    return x509.DNSName(alabel)

def _encode_SAN(emails, hosts, uris):
    return x509.SubjectAlternativeName(
                [x509.RFC822Name(e) for e in emails],
              + [_encode_host(ip) for ip in hosts] 
              + [x509.UniformResourceIdentifier(u) for u in uris]
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

    @classmethod
    def load(cls, cert_bytes: bytes, private_key_bytes: bytes,
                     password: Optional[str] = None) -> None:
        """Load a CA from an existing cert and private key.

        Args:
          cert_bytes: The bytes of the certificate in PEM format
          private_key_bytes: The bytes of the private key in PEM format
        """
        ca = cls()
        #ca.parent_cert = None
        ca._certificate = x509.load_pem_x509_certificate(cert_bytes)
        ca._private_key = load_pem_private_key(
                    private_key_bytes, password=password
        )
        return ca

    @classmethod
    def new(cls,
        name : x509.Name,
        path_length: int = 0,
        key_type : str = "ed25519",
        parent_cert: Optional["CA"] = None,
    ) -> None:
        """ Generate a new root CA.
        """
        self = cls()

        #self.parent_cert = parent_cert
        self._private_key = PrivIface(key_type).generate()
        self._path_length = path_length

        issuer = name
        sign_key = self._private_key
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

        cert_builder = _cert_builder_common(
            name, issuer, self._private_key.public_key()
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length),
            critical=True,
        )
        if aki:
            cert_builder = cert_builder.add_extension(aki, critical=False)
        self._certificate = cert_builder.add_extension(
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
            algorithm=None
            #algorithm=hashes.SHA256(),
        )
        return self

    def __str__(self):
        return str(self.cert_pem)

    @property
    def cert_pem(self) -> PublicBlob:
        """`Blob`: The PEM-encoded certificate for this CA. Add this to your
        trust store to trust this CA."""
        return PublicBlob(self._certificate)

    @property
    def private_key_pem(self) -> PrivateBlob:
        """`Blob`: The PEM-encoded private key for this CA. Use this to sign
        other certificates from this CA."""
        return PrivateBlob(self._private_key)

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
        return CA(parent_cert=self, path_length=path_length, key_type=key_type)

    def issue_cert(
        self,
        emails: List[str],
        hosts: List[str],
        uris: List[str],
        name: x509.Name,
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
          emails: The emails that this certificate will be valid for.

            - Email address: ``example@example.com``

          hosts:
            - Regular hostname: ``example.com``
            - Wildcard hostname: ``*.example.com``
            - International Domain Name (IDN): ``café.example.com``
            - IDN in A-label form: ``xn--caf-dma.example.com``
            - IPv4 address: ``127.0.0.1``
            - IPv6 address: ``::1``
            - IPv4 network: ``10.0.0.0/8``
            - IPv6 network: ``2001::/16``

          uris:
            - "https://dx.doi.org/10.1.1.1"

          name: x509 name (see `encode_name`)

          not_before: Set the validity start date (notBefore) of the certificate.
            This argument type is `datetime.datetime`.
            Defaults to now.

          not_after: Set the expiry date (notAfter) of the certificate. This
            argument type is `datetime.datetime`.
            Defaults to 365 days after `not_before`.

          key_type: Set the type of key that is used for the certificate. By default this is an ed25519 based key.

        Returns:
          LeafCert: the newly-generated certificate.

        """
        if not identities and common_name is None:
            raise ValueError("Must specify at least one identity or common name")

        key = key_type._generate_key()

        ski_ext = self._certificate.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        )
        aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            ski_ext.value
        )

        cert = (
            _cert_builder_common(
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
                _encode_SAN(emails, hosts, uris),
                critical=True,
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
                critical=True,
            )
            .sign(
                private_key=self._private_key,
                algorithm=None
                #algorithm=hashes.SHA256(),
            )
        )

        return LeafCert(
            PrivateBlob(key).bytes(),
            PublicBlob(cert).bytes()
        )

    # For backwards compatibility
    issue_server_cert = issue_cert

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
        self, private_key_pem: bytes, server_cert_pem: bytes, chain_to_ca: List[bytes] = []
    ) -> None:
        self.private_key_pem = Blob(private_key_pem, "private")
        self.cert_chain_pems = [Blob(pem, "public") for pem in [server_cert_pem] + chain_to_ca]
        self.private_key_and_cert_chain_pem = Blob(
            private_key_pem + server_cert_pem + b"".join(chain_to_ca),
            "private"
        )

    def configure_cert(self, ctx: ssl.SSLContext) -> None:
        """Configure the given context object to present this certificate.

        Args:
          ctx: The SSL context to be modified.
        """
        # Currently need a temporary file for this, see:
        #   https://bugs.python.org/issue16487
        with self.private_key_and_cert_chain_pem.tempfile() as path:
            ctx.load_cert_chain(path)

def new_ca():
    name = encode_name("My Company", "My Division", "mycompany.com")
    ca = CA.new(name)
    return ca
    # Generate our key
    #root_key = ec.generate_private_key(ec.SECP256R1())
    root_key = PrivIface("ed25519").generate()
    
    root_cert = (cert_builder_common(subject, issuer, root_key.public_key())
        . add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True)
        . add_extension(
                x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension( _encode_SAN(emails, hosts, uris),
            critical=True,
        ).sign(root_key, None) ) # hashes.SHA256()
    return root_cert

ca = new_ca()
print(ca)
