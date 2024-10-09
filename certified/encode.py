""" Functionality for encoding parts of x509 certificates.
"""

from typing import Optional, List, Tuple, Any, Union
from enum import Enum
import datetime
import ipaddress
import idna

from cryptography.hazmat.primitives.asymmetric import (
    ed448, 
    ed25519,
    ec
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
)

from .blob import *

__all__ = ["SAN", "name", "PrivIface", "hash_for_pubkey",
           "cert_builder_common", "get_aki",
           "CertificateIssuerPrivateKeyTypes",
           "CertificatePublicKeyTypes",
           "append_pseudonym", "get_urls", "rfc4514name",
           "get_path_length", "get_is_ca"
          ]

class PrivIface:
    def __init__(self, keytype : str) -> None:
        self.ed : Optional[type[Union[
            ed25519.Ed25519PrivateKey,ed448.Ed448PrivateKey
                ]]] = None
        self.ec : Optional[ Any ] = None
        if keytype == "ed25519":
            self.ed = ed25519.Ed25519PrivateKey
        elif keytype == "ed448":
            self.ed = ed448.Ed448PrivateKey
        elif keytype == "secp256r1":
            self.ec = ec.SECP256R1
        elif keytype == "secp384r1":
            self.ec = ec.SECP384R1
        elif keytype == "secp521r1":
            self.ec = ec.SECP521R1
        elif keytype == "secp256k1":
            self.ec = ec.SECP256K1
        else:
            raise KeyError(keytype)

    def hash_alg(self) -> Optional[hashes.SHA256]:
        if self.ed:
            return None
        return hashes.SHA256()
        #return hashes.BLAKE2b(64)
        # cryptography.exceptions.UnsupportedAlgorithm: Hash algorithm "blake2b" not supported for signatures

    def generate(self) -> CertificateIssuerPrivateKeyTypes:
        if self.ec:
            return ec.generate_private_key(self.ec())
        elif self.ed:
            return self.ed.generate()
        raise KeyError("Invalid key type.")

    def __eq__(a, b):
        return a.ed == b.ed and a.ec == b.ec

def hash_for_pubkey(pkey : CertificatePublicKeyTypes
                   ) -> Optional[hashes.SHA256]:
    if isinstance(pkey, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        return None
    return hashes.SHA256()

Location = Tuple[Optional[str],Optional[str],Optional[str]]

def person_name(
    name : str,
    uname : Optional[str] = None,
    domain : List[str] = [],
    #email : Optional[str] = None, # deprecated.
    location: Location = (None, None, None),
    pseudonym: Optional[str] = None,
) -> x509.Name:
    """ Build and return an x509.Name suitable for an individual.
    """
    #   (NameOID.EMAIL_ADDRESS, email)

    country, state, city = location

    name_pieces = []
    for oid, val in [
                (NameOID.COMMON_NAME, name),
                (NameOID.USER_ID, uname),
                (NameOID.PSEUDONYM, pseudonym),
                (NameOID.COUNTRY_NAME, country),
                (NameOID.STATE_OR_PROVINCE_NAME, state),
                (NameOID.LOCALITY_NAME, city)
            ] + [
                (NameOID.DOMAIN_COMPONENT, dn) for dn in domain
            ]:
        if val:
            name_pieces.append(x509.NameAttribute(oid, val))

    return x509.Name(name_pieces)

def org_name(
    organization_name: str,
    unit_name: str,
    common_name: Optional[str] = None,
    domain: List[str] = [],
    location: Location = (None,None,None),
    pseudonym: Optional[str] = None,
) -> x509.Name:
    """ Build and return an x509.Name suitable for an organization.

    Args:
       organization_name: Sets the "Organization Name" (O)
           attribute on the certificate.

       unit_name: Sets the "Organization Unit Name" (OU)
           attribute on the certificate.
    
       common_name: Sets the "Common Name" of the certificate. This is a
           legacy field that used to be used to check identity. It's an
           arbitrary string with poorly-defined semantics, so
           [modern programs are supposed to ignore it](https://developers.google.com/web/updates/2017/03/chrome-58-deprecations#remove_support_for_commonname_matching_in_certificates).
           But it might be useful if you need to test how your software
           handles legacy or buggy certificates.

       location: Optionally a tuple containing:
           (country_code, state_or_province, city_or_locality)

       pseudonym: Used here to denote whether this is a signing key.
    """

    country, state, city = location

    name_pieces = []
    for oid, val in [
                (NameOID.ORGANIZATION_NAME, organization_name),
                (NameOID.ORGANIZATIONAL_UNIT_NAME, unit_name),
                (NameOID.COMMON_NAME, common_name),
                (NameOID.PSEUDONYM, pseudonym),
                (NameOID.COUNTRY_NAME, country),
                (NameOID.STATE_OR_PROVINCE_NAME, state),
                (NameOID.LOCALITY_NAME, city)
            ] + [
                (NameOID.DOMAIN_COMPONENT, dn) for dn in domain
            ]:
        if val:
            name_pieces.append(x509.NameAttribute(oid, val))

    return x509.Name(name_pieces)

def append_pseudonym(name : x509.Name, ps : str) -> x509.Name:
    """
    Append a NameOID.PSEUDONYM field to the name
    with the given value.

    Used by certified to create a unique name for the
    signing certificate by appending ps = "Signing Certificate"

    Args:
      name: the base name
      ps: appended pseudonym
    """
    parts = [n for n in name]
    parts.append( x509.NameAttribute(NameOID.PSEUDONYM, ps) )
    return x509.Name(parts)

# Code in this function was originally derived from
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
def cert_builder_common(
        subject: x509.Name,
        issuer: x509.Name,
        public_key: CertificatePublicKeyTypes,
        not_before: Optional[datetime.datetime] = None,
        not_after: Optional[datetime.datetime] = None,
        self_signed: bool = False,
    ) -> x509.CertificateBuilder:
    """
    Common part of the certificate building process.

    Factored into some re-usable code that automatically
    sets up valid date ranges and checks that your
    name won't collide with what you're signing.
    """
    not_before = not_before if not_before else datetime.datetime.now(datetime.timezone.utc)
    # default valid for ~1 years
    not_after = not_after if not_after else (
            not_before + datetime.timedelta(days=365)
    )
    if self_signed:
        assert subject == issuer, "Self-signed certificate, but subject != issuer"
    else:
       assert subject != issuer, "Cannot have subject == issuer for normal certificate."

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

# Code in this function was originally derived from
# https://github.com/python-trio/trustme
#
# It was made available from that project under terms of the
# MIT license, reproduced in this file just
# above the cert_builder_common function.
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

def get_urls(cert : x509.Certificate) -> List[str]:
    try:
        san = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
    except x509.ExtensionNotFound:
        return []

    urls = []
    for n in san.value:
        print(n)
        if isinstance(n, x509.DNSName):
            urls.append(n.value)
        elif isinstance(n, x509.IPAddress):
            urls.append(str(n.value))
    return urls

def get_aki(cert : x509.Certificate) -> x509.AuthorityKeyIdentifier:
    """ Collect the SubjectKeyIdentifier from a certificate
        and return it as an AuthorityKeyIdentifier.
        The content should be the same, but they have different
        header / wrappers.
    """
    try:
        ski_ext = cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        )
    except x509.ExtensionNotFound:
        raise
        # we want the pubkey to match, so skip this.
        return x509.AuthorityKeyIdentifier.from_issuer_public_key(
                cert.public_key()
        )
    return x509.AuthorityKeyIdentifier \
               .from_issuer_subject_key_identifier(ski_ext.value)

def rfc4514name(subject: x509.Name):
    # By default, attributes CN, L, ST, O, OU, C, STREET, DC, UID are represented by their short name
    # CN      commonName (2.5.4.3)
    # L       localityName (2.5.4.7)
    # ST      stateOrProvinceName (2.5.4.8)
    # O       organizationName (2.5.4.10)
    # OU      organizationalUnitName (2.5.4.11)
    # C       countryName (2.5.4.6)
    # STREET  streetAddress (2.5.4.9)
    # DC      domainComponent (0.9.2342.19200300.100.1.25)
    # UID     userId (0.9.2342.19200300.100.1.1)
    #
    # but, rfc5280 says we MUST be prepared for
    #   x country
    #   x organization
    #   x organizational unit
    #   - distinguished name qualifier,
    #   x state or province name,
    #   x common name (e.g., "Susan Housley"), and
    #   - serial number.
    # and SHOULD be prepared for
    #   x locality,
    #   - title,
    #   - surname,
    #   - given name,
    #   - initials,
    #   - pseudonym, and
    #   - generation qualifier (e.g., "Jr.", "3rd", or "IV").
    #
    # apparently, STREET, UID, and DC are "free"

    return subject.rfc4514_string({
                NameOID.PSEUDONYM: "P",
                NameOID.DN_QUALIFIER: "DQ",
                NameOID.SERIAL_NUMBER: "S",
                NameOID.EMAIL_ADDRESS: "E",
                NameOID.TITLE: "T",
                NameOID.SURNAME: "SUR",
                NameOID.GIVEN_NAME: "NAME",
                NameOID.INITIALS: "IN",
                NameOID.GENERATION_QUALIFIER: "GEN"
           })

def get_path_length(cert: x509.Certificate) -> Optional[int]:
    try:
        basic = cert.extensions \
                    .get_extension_for_class(x509.BasicConstraints)
        return basic.value.path_length
    except x509.ExtensionNotFound:
        raise ValueError("BasicConstraints not found.")

def get_is_ca(cert: Union[x509.CertificateSigningRequest,
                          x509.Certificate]) -> bool:
    try:
        basic = cert.extensions \
                    .get_extension_for_class(x509.BasicConstraints)
        return basic.value.ca
    except x509.ExtensionNotFound:
        return False
        raise ValueError("BasicConstraints not found.")
