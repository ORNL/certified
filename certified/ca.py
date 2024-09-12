""" A module for holding x509 signing certificates (CA)
    and leaf certificates (LeafCert)
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

from typing import Optional, List, Callable, Union
import datetime
import ssl

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import (
    ed25519,
)
import biscuit_auth as bis

from .cert_base import FullCert

from .blob import PublicBlob, PrivateBlob, Blob, PWCallback
import certified.encode as encode
from .encode import cert_builder_common
from .serial import cert_to_pem
from .cert_info import CertInfo

class CA(FullCert):
    """ CA-s are used only to sign other certificates.
        Separating CA-s from the `LeafCert`-s used to authenticate
        TLS participants is required if one wants to use keys
        for either signing or key derivation, but not both.

        Note that while elliptic curve keys can technically
        be used for both signing and key exchange, this is considered
        [bad cryptographic practice](https://crypto.stackexchange.com/a/3313).
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
        assert encode.get_is_ca(self._certificate), \
                "Loaded certificate is not a CA."

    def issue_cert(self, info : CertInfo,
                   not_before: Optional[datetime.datetime] = None,
                   not_after: Optional[datetime.datetime] = None,
                   path_length : Optional[int] = None
                  ) -> x509.Certificate:
        """Issue the certificate described by `info`.

        Danger: Do not use this function unless you understand
                how the resulting certificate will be used.

        Args:
          info: the certificate `CertInfo` object

          not_before: Set the validity start date (notBefore) of the certificate.
            This argument type is `datetime.datetime`.
            Defaults to now.

          not_after: Set the expiry date (notAfter) of the certificate. This
            argument type is `datetime.datetime`.
            Defaults to 365 days after `not_before`.

          path_length: desired path length (None for end-entity)

        Returns:
          cert: The newly-generated certificate.
        """

        cert_builder = info.build(
                            self._certificate,
                            not_before = not_before,
                            not_after = not_after,
                            path_length = path_length
                        )
        return self._sign_cert( cert_builder )

    def _sign_cert(self, builder) -> x509.Certificate:
        """Sign a certificate.

        Danger: Do not use this function unless you understand
                how the resulting certificate will be used.

        Note: Consider using `sign_csr` instead of this function.

        Args:
          builder: the certificate builder before signature
        """
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

        info = CertInfo(name,
                        san,
                        private_key.public_key(),
                        is_ca = True)

        if parent_cert:
            certificate = parent_cert.issue_cert(info,
                                            path_length=path_length)
        else:
            certificate = info.build( None,
                                      path_length=path_length ) \
                              . sign( private_key,
                                 encode.PrivIface(key_type).hash_alg()
                                )
        return cls(PublicBlob(certificate).bytes(),
                   PrivateBlob(private_key).bytes())

    def leaf_cert(
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
        info = CertInfo(name, san, key.public_key(), False)

        cert = self.issue_cert(info,
                    not_before = not_before,
                    not_after = not_after,
                    path_length = None
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
        ctx.load_verify_locations(cadata=cert_to_pem(self.certificate))


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
            ctx.load_cert_chain(path)
