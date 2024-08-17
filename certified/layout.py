"""Defines the format for the certified-apis configuration directory

This is usually stored in $VIRTUAL_ENV/etc/certified
but can be overriden by the value of $CERTIFIED_CONFIG
in the environment.

The configuration uses a $HOME/.ssh directory-style
layout.  See details in [docs/keys](/docs/keys.md).
"""

from typing import Union, Optional, Tuple, List, Any, Callable
import os
import shutil
from urllib.parse import urlparse
import ssl
from pathlib import Path
from functools import cache
from contextlib import contextmanager

from cryptography import x509

try:
    import httpx
except ImportError:
    httpx = None

from .blob import Blob, is_user_only
from .wrappers import ssl_context
from .ca import CA, LeafCert

PWCallback = Callable[(), str]
Pstr = Union[str, "os.PathLike[str]"]

def fixed_ssl_context(
    certfile: str | os.PathLike[str],
    keyfile: str | os.PathLike[str] | None,
    password,
    ssl_version: int,
    cert_reqs: int,
    ca_certs: str | os.PathLike[str] | None,
    ciphers: str | None,
) -> ssl.SSLContext:
    ctx = ssl_context(is_client = False)
    #ctx.verify_mode = ssl.VerifyMode(cert_reqs) # already required by (our) default

    if ciphers:
        ctx.set_ciphers(ciphers)

    ctx.load_cert_chain(certfile, keyfile, password)
    if ca_certs:
        if not Path(ca_certs).exists():
            ctx.load_verify_locations(cadata=ca_certs)
        elif Path(ca_certs).is_dir():
            ctx.load_verify_locations(capath=ca_certs)
        else:
            ctx.load_verify_locations(cafile=ca_certs)
    return ctx

try:
    import uvicorn
    uvicorn.config.create_ssl_context = fixed_ssl_context
except ImportError:
    uvicorn = None

@cache
def config(certified_config : Optional[Pstr] = None,
           should_exist=True) -> Path:
    """Lookup and return the location of the certified-apis
    configuration directory.

    Priority order is:
      1. certified_config (if not None)
      2. $CERTIFIED_CONFIG (if CERTIFIED_CONFIG defined)
      3. $VIRTUAL_ENV/etc/certified (if VIRTUAL_ENV defined)
      4. /etc/certified

    Note: The return value of this function is cached,
          so changes to environment variables have
          no effect after the first return from this function.

    Args:
      certified_config: if defined, this value is returned.
      should_exist: require that the directory exist?

    Raises:
      NotADirectoryError: Raised if the config does not point to a directory.
                          If exists == False, this is only raised
                          when the config exists,
                          but is not a non-directory.

    """
    if certified_config is None:
        try:
            certified_config = os.environ["CERTIFIED_CONFIG"]
        except KeyError:
            pre = os.environ.get("VIRTUAL_ENV", "/")
            certified_config = Path(pre)/"etc"/"certified"

    p = Path(certified_config)
    if should_exist:
        if not p.is_dir():
            raise NotADirectoryError(str(p))
    else:
        if p.exists() and not p.is_dir():
            raise NotADirectoryError(str(p))
    return p

class CRTDir:
    """ Interface to a directory containing PEM-formatted
        certificates.
    """
    def __init__(self, base : Path):
        self.base = base

    def __getitem__(self, name):
        return Blob.read(name + ".crt")

    # Note: openssl's -CApath option points to
    # a directory of these, so we can use that to specify
    # a directory of trust roots, if available.

    #def check(self):
    #    for child in self.base.iterdir():
    #        assert not child.is_dir()
    #        assert child.suffix == ".crt", "Invalid format."

class Identity(CRTDir):
    def __init__(self, base : Path):
        super().__init__(base)

    def key(self, name : Pstr) -> Blob:
        return Blob.read(name + ".key")

def check_config(base : Path) -> Tuple[List[str], List[str]]:
    """ Scans the base configuration directory and
        returns a list of warnings and error messages.
        
        >>> cfg = certified.config()
        >>> warn, err = certified.check(cfg)
        >>> if len(err) > 0:
        >>>    print(f"{len(err)} errors:")
        >>>    print("\n".join(err))
    """
    warnings : List[str] = []
    errors : List[str] = []
    def error(err):
        nonlocal errors
        errors.append(err)
        return warnings, errors
    def warn(s):
        nonlocal warnings
        warnings.append(s)
    def gone(p):
        if not p.exists():
            error(f"{p} does not exist")
        elif p.is_dir():
            error(f"{p} exists, but is a directory")
        elif p.is_file():
            error(f"{p} exists, but is a file")
        error(f"{p} exists, but is neither a file nor a directory")
        return warnings, errors
            
    def notexist(f):
        error(f"{p} does not exist.")
    if not base.is_dir():
        return gone(base)

    key = base/"CA.key"
    if not (key).is_file():
        gone(key)
    if not is_user_only(key):
        error(f"Invalid key file permissions on {key}!")
    if not (base/"CA.crt").is_file():
        gone(base/"CA.crt")
    if not (base/"known_clients").is_dir():
        gone(base/"known_clients")
    if not (base/"known_servers").is_dir():
        gone(base/"known_servers")

    fca = base / "CA.crt"
    CA = Blob.read(fca)
    for fself in [ base/"known_servers"/"self.crt"
                 , base/"known_clients"/"self.crt" ]:
        if fself.is_file():
            stest = Blob.read(fself)
            if CA.bytes() != stest.bytes():
                warn(f"{fself} does not match {fca}")
        else:
            warn(f"{fself} does not exist.")

    return warnings, errors

class Certified:
    def __init__(self, certified_config : Optional[Pstr] = None):
        self.config = config(certified_config)

    def signer(self):
        return CA.load(self.config / "CA")

    def identity(self):
        return LeafCert.load(self.config / "0")

    def ssl_context(self, is_client : bool) -> ssl.SSLContext:
        ctx = ssl_context(is_client)
        self.identity().configure_cert( ctx )
        if is_client:
            ctx.load_verify_locations(capath=self.config/"known_servers")
        else:
            ctx.load_verify_locations(capath=self.config/"known_clients")
        return ctx

    @classmethod
    def new(cls,
            name1 : x509.Name,
            name2 : x509.Name,
            san : x509.SubjectAlternativeName,
            certified_config : Optional[Pstr] = None,
            overwrite : bool = False,
           ) -> "Certified":
        """ Create a new CA and identity certificate
        
        Args:
          name1: the distinguished name for the signing key
          name2: the distinguished name for the end-entity
          san:   subject alternate name fields for both certificates
          certified_config: base directory to output the new identity
          overwrite: if True, any existing files will be deleted first
        """
        ca    = CA.new(name1, san)
        ident = ca.issue_cert(name2, san)

        cfg = config(certified_config, False)
        if overwrite: # remove existing config!
            try:
                shutil.rmtree(cfg)
            except FileNotFoundError:
                pass
        else:
            try:
                cfg.rmdir() # only succeeds if dir. is empty
            except FileNotFoundError: # not created yet - OK
                pass
            except OSError:
                raise FileExistsError(cfg)
        cfg.mkdir(exist_ok=True, parents=True)

        ca.save(cfg / "CA", False)
        ident.save(cfg / "0", False)

        (cfg/"known_servers").mkdir()
        (cfg/"known_clients").mkdir()
        shutil.copy(cfg/"CA.crt", cfg/"known_servers"/"self.crt")
        shutil.copy(cfg/"CA.crt", cfg/"known_clients"/"self.crt")
        return cls(cfg)

    @contextmanager
    def Client(self, prefix):
        cfg = self.config
        headers = {'user-agent': 'certified-client/0.1.0'}
        ident = self.identity()

        assert httpx is not None, "httpx is not available."

        ssl_ctx = self.ssl_context(is_client = True)
        with httpx.Client(base_url = prefix,
                          headers = headers,
                          verify = ssl_ctx) as client:
            yield client

    def serve(self,
              app : Any,
              url_str : str,
              get_passwd : PWCallback = None) -> None:
        cfg = self.config
        url = urlparse(url_str)

        if url.scheme == "https":
            assert url.hostname is not None, "URL must define a hostname."
            assert url.port is not None, "URL must define a port."
            assert uvicorn is not None, "uvicorn is not available."

            uvicorn.run(app,
                        host=url.hostname,
                        port=url.port,
                        log_level="info",
                        ssl_cert_reqs=ssl.VerifyMode.CERT_REQUIRED,
                        ssl_ca_certs=cfg/"known_clients",
                        ssl_certfile=cfg/"0.crt",
                        ssl_keyfile=cfg/"0.key",
                        ssl_keyfile_password=get_passwd,
                        http="h11")
        else:
            raise ValueError(f"Unsupported URL scheme: {url.scheme}")
