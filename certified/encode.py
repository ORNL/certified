""" Functionality for generating certificates.
"""

from typing import Optional, List
from enum import Enum
import datetime
import ipaddress
import idna

from cryptography.hazmat.primitives.asymmetric import (
    ed448, 
    ed25519
)
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificatePublicKeyTypes,
    CertificateIssuerPrivateKeyTypes
)
#from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from cryptography import x509
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)

from .blob import *

__all__ = ["SAN", "name", "PrivIface", "PubIface",
           "cert_builder_common",
           "CertificateIssuerPrivateKeyTypes",
           "CertificatePublicKeyTypes"
          ]

def PrivIface(keytype) -> CertificateIssuerPrivateKeyTypes:
    if keytype == "ed25519":
        return ed25519.Ed25519PrivateKey
    elif keytype == "ed448":
        return ed448.Ed448PrivateKey
    # support P-256?
    #return ec.generate_private_key(ec.SECP256R1())

def PubIface(keytype) -> CertificatePublicKeyTypes:
    if keytype == "ed25519":
        return ed25519.Ed25519PublicKey
    elif keytype == "ed448":
        return ed448.Ed448PublicKey


def cert_builder_common(
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

def name(
    organization_name: str,
    unit: str,
    common_name: Optional[str] = None,
) -> x509.Name:
    """
    Build and return an x509.Name.

    Args:
       organization_name: Sets the "Organization Name" (O) attribute on the
            certificate.

       unit: Sets the "Organization Unit Name" (OU)
            attribute on the certificate.
    
       common_name: Sets the "Common Name" of the certificate. This is a
         legacy field that used to be used to check identity. It's an
         arbitrary string with poorly-defined semantics, so `modern
         programs are supposed to ignore it
         <https://developers.google.com/web/updates/2017/03/chrome-58-deprecations#remove_support_for_commonname_matching_in_certificates>`__.
         But it might be useful if you need to test how your software
         handles legacy or buggy certificates.

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
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, unit),
    ]
    if common_name is not None:
        name_pieces.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
    return x509.Name(name_pieces)

def _host(host):
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

def SAN(emails=[], hosts=[], uris=[]) -> x509.SubjectAlternativeName:
    """ Build a subject alternative name field.
        Examples include:

        * emails: The emails that this certificate will be valid for.

            - Email address: ``example@example.com``

        * hosts:
            - Regular hostname: ``example.com``
            - Wildcard hostname: ``*.example.com``
            - International Domain Name (IDN): ``café.example.com``
            - IDN in A-label form: ``xn--caf-dma.example.com``
            - IPv4 address: ``127.0.0.1``
            - IPv6 address: ``::1``
            - IPv4 network: ``10.0.0.0/8``
            - IPv6 network: ``2001::/16``

        * uris:
            - "https://dx.doi.org/10.1.1.1"
    """
    assert sum(map(len, [emails, hosts, uris])) > 0, "No identities provided."
    return x509.SubjectAlternativeName(
                [x509.RFC822Name(e) for e in emails]
              + [_host(ip) for ip in hosts] 
              + [x509.UniformResourceIdentifier(u) for u in uris]
           )

