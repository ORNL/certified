import os
from typing import Literal, Union, Optional, Generator
from tempfile import NamedTemporaryFile
from pathlib import Path
from contextlib import contextmanager

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

__all__ = ["Blob", "PublicBlob", "PrivateBlob"]

Pstr = Union[str, "os.PathLike[str]"]

@contextmanager
def set_umask(umask):
    prev_umask = os.umask(umask)
    try:
        yield
    finally:
        os.umask(prev_umask)

@contextmanager
def new_file(fname : Pstr, mode : int, perm : int, remove=False):
    """ Fix the file open() API to create
        new files securely.
    """
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
    #umask = 0o777 ^ perm  # Prevents always downgrading umask to 0.

    if remove:
        try:
            os.remove(fname)
        except FileNotFoundError:
            pass

    #with set_umask(umask):
    # open fails if file exists
    fdesc = os.open(fname, flags, perm)
    with os.fdopen(fdesc, mode) as f:
        # this context closes fd on completion
        yield f

def is_user_only(fname) -> bool:
    stat = os.stat(fname)
    return (stat.st_mode & 0o77) == 0

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
        return cls(data, "secret" if is_secret else "public")

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
        if append:
            if self.is_secret:
                assert is_user_only(p)
            ctxt = lambda: p.open("ab")
        else:
            if self.is_secret:
                ctxt = lambda: new_file(p, "wb", 0o600)
            else:
                ctxt = lambda: new_file(p, "wb", 0o644)
                #ctxt = lambda: p.open("wb")

        with ctxt() as f:
            f.write(self._data)

    @contextmanager
    def tempfile(self, dir: Optional[str] = None) -> Generator[str, None, None]:
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
    def __init__(self, cert : x509) -> None:
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
