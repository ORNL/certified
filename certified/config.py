"""Defines the format for the certified-apis configuration file.

This is usually stored in $HOME/.config/certified.json
but can be overriden by the value of $CERTIFIED_CONFIG
in the environment.

Note: at present, this is a single configuration file.
However, we should really use a $HOME/.ssh directory-style
layout with:

    - authorized_keys -- listing `TrustedClient`-s
    - known_hosts -- listing `TrustedService`-s
    - id_<type>.pub, id_type -- listing name/privkeys
     //- grants (actually, we probably shouldn't cache these globally)
"""

from typing import Dict, Set, Optional, TypedDict

from pydantic import BaseModel, Field, SecretBytes

URL = str

# We assume DER-encoding for all these things (although PEM is an alternative)
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/

from cryptography.hazmat.primitives.serialization import (
    load_der_private_key,
    load_der_public_key
)
from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes,
    CertificatePublicKeyTypes
)

class PrivKey(BaseModel):
    data : SecretBytes # DER-encoded

    def privkey(self, password : Optional[str] = None) -> PrivateKeyTypes:
        """Returns the private key object associated with this key.
   
        Args:
            password: Password to decipher private key (if required).
        """
        return load_der_private_key(self.data.get_secret_value(), password)

    def pubkey(self, password=None) -> CertificatePublicKeyTypes:
        """Returns the public key object associated with this key.
   
        Args:
            password: Password to decipher private key (if required).
        """
        return self.privkey(password).public_key()

class PubKey(BaseModel):
    data : bytes # DER-encoded

    def pubkey(self) -> CertificatePublicKeyTypes:
        """Returns the public key object associated with this key.
        """
        return load_der_public_key(self.data)

class TrustedClient(BaseModel):
    """
    Defines a client.
    
    These clients are the "ultimate" trusted
    sources for a validation chain.

    In the default grant validation policy, all `TrustedClient`-s
    are allowed to do the listed scopes.
    """
    pubkey : PubKey
    scopes : Set[str] = set()

class TrustedService(BaseModel):
    """
    Defines a service provider.  To be used by potential
    clients to determine how to connect with the service.
    
    These services are accessible by sending messages
    to the URL -- identifying the server via the pubkey.

    These providers are the "ultimate" trusted
    sources for a validation chain.

    The scopes attribute here defines the requested
    scopes from the provider.  The actual granted scopes
    depend on the server's configuration.

    For `Config.validator`-s, replace "service" with "validator"
    in the explanations of the fields below, except for these fields:

        * scopes = set of scopes this validator is allowed to grant
        * auths  = ignored
    """
    url    : URL              # service base URL
    pubkey : PubKey           # service public key
    scopes : Set[str] = set() # scopes client should request when using this service
    auths  : Set[str] = set() # names of validators recognized by this service

class Config(BaseModel):
    """ Actor-level configuration file.
        Contains the actor's private key, listening port,
        and a list of trusted communication parties.
    """
    name       : str
    privkey    : PrivKey
    listen     : Optional[URL] = None
    clients    : Dict[str, TrustedClient]  = {}
    services   : Dict[str, TrustedService] = {}
    #: alternative to client authentication (ca root store)
    validators : Dict[str, TrustedService] = {}
    #: store of grants (to auth. to other services)
    grants     : Dict[str, SignedGrant] = {}

# anyPolicy has n = "0"
# since (RFC 5280)
#     anyPolicy OBJECT IDENTIFIER ::= { id-ce-certificatePolicies 0 }
#     id-ce-certificatePolicies OBJECT IDENTIFIER ::=  { id-ce 32 }
#     id-ce   OBJECT IDENTIFIER ::=  { joint-iso-ccitt(2) ds(5) 29 }
#
# encodedPolicyID = lambda n: f"2.5.29.32.{n}"
#
# Note, the policy OID can be any OID (sequence of numbers),
# and the standard encoding in the x509 prefixes that with 2.5.29.32.
#
# Hence, we can choose to encode strings as policy ID-s
# if we use ASN.1 printableString or utf8String encoding:
#
#     policyOID = 19.(length).[list of length "printable" characters]
#     policyOID = 12.(length).[UTF-8 sequence of "length" bytes]
# 
# then, we can use the strings to name scopes (e.g. 'admin' 'audit')
# or hack those strings to equal datalog facts
# (e.g. 'scope("admin")' 'scope("audit")')

