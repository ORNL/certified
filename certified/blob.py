import os
from typing import Literal, Union, Optional, Iterator, IO, Any, Callable
from tempfile import NamedTemporaryFile
from pathlib import Path
from contextlib import contextmanager, AbstractContextManager

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)

__all__ = ["Blob", "PublicBlob", "PrivateBlob", "Pstr", "PWCallback"]

Pstr = Union[str, "os.PathLike[str]"]
PWCallback = Optional[Callable[[], bytes]]

@contextmanager
def new_file(fname : Pstr, mode : str, perm : int,
             remove=False) -> Iterator[IO[Any]]:
    """ Fix the file open() API to create
        new files securely.

        Ref: https://stackoverflow.com/questions/5624359/write-file-with-specific-permissions-in-python @Asclepius
    """
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL

    if remove:
        try:
            os.remove(fname)
        except FileNotFoundError:
            pass

    # open fails if file exists
    fdesc = os.open(fname, flags, perm)
    with os.fdopen(fdesc, mode) as f:
        # this context closes fd on completion
        yield f

def is_user_only(fname) -> bool:
    stat = os.stat(fname)
    return (stat.st_mode & 0o77) == 0

# This class is derived from https://github.com/python-trio/trustme
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
#
class Blob:
    """A convenience wrapper for a blob of bytes, mostly
    representing PEM-encoded data.

    Args:
      data: the PEM-encoded data.
      secret: either "public" or "secret" (setting file permissions for I/O)
    """

    def __init__(self, data: bytes, is_secret : bool) -> None:
        self._data = data
        self.is_secret = is_secret

    @classmethod
    def read(cls, fname: Pstr) -> "Blob":
        is_secret = is_user_only(fname)
        with open(fname, "rb") as f:
            data = f.read()
        return cls(data, is_secret)

    def bytes(self) -> bytes:
        """Returns the data as a `bytes` object."""
        return self._data

    def __str__(self) -> str:
        if self.is_secret:
            return "*********"
        return self.bytes().decode("ascii")

    def write(
        self, path: Pstr, append: bool = False
    ) -> None:
        """Writes the data to the file at the given path.

        Args:
          path: The path to write to.
          append: If False (the default), replace any existing file
               with the given name. If True, append to any existing file.
        """
        p = Path(path)
        ctxt : AbstractContextManager[IO[Any]]
        if append:
            if self.is_secret:
                assert is_user_only(p)
            ctxt = p.open("ab")
        else:
            if self.is_secret:
                ctxt = new_file(p, "wb", 0o600)
            else:
                ctxt = new_file(p, "wb", 0o644)
                #ctxt = p.open("wb")

        with ctxt as f:
            f.write(self._data)

    @contextmanager
    def tempfile(self, dir: Optional[str] = None) -> Iterator[str]:
        """Context manager for writing data to a temporary file.

        The file is created when you enter the context manager, and
        automatically deleted when the context manager exits.

        Many libraries have annoying APIs which require that certificates be
        specified as filesystem paths, so even if you have already the data in
        memory, you have to write it out to disk and then let them read it
        back in again. If you encounter such a library, you should probably
        file a bug. But in the mean time, this context manager makes it easy
        to give them what they want.

        Example:

          Here's how to get requests to use a CA (`see also
          <http://docs.python-requests.org/en/master/user/advanced/#ssl-cert-verification>`__)::

           ca = certified.CA()
           with ca.cert_pem.tempfile() as ca_cert_path:
               requests.get("https://localhost/...", verify=ca_cert_path)

        Args:
          dir: Passed to `tempfile.NamedTemporaryFile`.

        """
        with NamedTemporaryFile(suffix=".pem", dir=dir, delete=False) as f:
            try:
                os.chmod(f.name, 0o600)
                f.write(self._data)
                f.close()
                yield f.name
            finally:
                f.close() # in case chmod() or write() raised an error
                os.unlink(f.name)

class PublicBlob(Blob):
    def __init__(self, cert : Union[x509.Certificate,
                                    x509.CertificateSigningRequest]) -> None:
        super().__init__(cert.public_bytes(Encoding.PEM), False)

class PrivateBlob(Blob):
    def __init__(self, key : CertificateIssuerPrivateKeyTypes) -> None:
        try:
            pkey = key.private_bytes(
                Encoding.PEM,
                PrivateFormat.PKCS8,
                NoEncryption())
        except ValueError:
            pkey = key.private_bytes(Encoding.PEM,
                PrivateFormat.TraditionalOpenSSL,
                #PrivateFormat.PKCS8,
                #PrivateFormat.OpenSSH,
                NoEncryption())
        super().__init__(pkey, True)
