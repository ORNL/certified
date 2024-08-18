import os
from typing import Union, Optional, Tuple, List, Any, Callable, Dict
from urllib.parse import urlparse
from contextlib import contextmanager
from pathlib import Path
import ssl
import shutil
import logging
_logger = logging.getLogger(__name__)

from cryptography import x509

import certified.layout as layout
from .ca import CA, LeafCert
from .wrappers import ssl_context, configure_capath
from .blob import Pstr

PWCallback = Callable[(), str]

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
    _logger.info("Using Certified's custom ssl context.")

    if ciphers:
        ctx.set_ciphers(ciphers)

    ctx.load_cert_chain(certfile, keyfile, password)
    if ca_certs:
        ca_cert_path = Path(ca_certs)
        if not ca_cert_path.exists():
            ctx.load_verify_locations(cadata=ca_certs)
        elif ca_cert_path.is_dir():
            _logger.debug("reading certificates in %s to cadata since "
                    "capath option to load_verify_locations is "
                    "known not to work", ca_certs)
            #ctx.load_verify_locations(capath=ca_certs)
            configure_capath(ctx, ca_cert_path)
        else:
            ctx.load_verify_locations(cafile=ca_certs)
    return ctx


try:
    import uvicorn
    uvicorn.config.create_ssl_context = fixed_ssl_context
    # https://github.com/encode/uvicorn/discussions/2307
    from uvicorn.protocols.http.h11_impl import RequestResponseCycle
    responseCycleInit = RequestResponseCycle.__init__
    def monkey_patch_response_cycle(self,*k,**kw):
        responseCycleInit(self,*k,**kw)
        self.scope['transport'] = self.transport
    RequestResponseCycle.__init__ = monkey_patch_response_cycle
except ImportError:
    uvicorn = None

try:
    import httpx
except ImportError:
    httpx = None

class Certified:
    def __init__(self, certified_config : Optional[Pstr] = None):
        self.config = layout.config(certified_config)

    def signer(self):
        return CA.load(self.config / "CA")

    def identity(self):
        return LeafCert.load(self.config / "0")

    def ssl_context(self, is_client : bool) -> ssl.SSLContext:
        ctx = ssl_context(is_client)
        self.identity().configure_cert( ctx )
        if is_client:
            configure_capath(ctx, self.config/"known_servers")
        else:
            configure_capath(ctx, self.config/"known_clients")
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

        cfg = layout.config(certified_config, False)
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
    def Client(self, base_url, headers : Dict[str,str] = {}):
        """ Create an httpx.Client context
            that includes the current identity within
            its ssl context.
        """
        assert httpx is not None, "httpx is not available."

        ssl_ctx = self.ssl_context(is_client = True)
        with httpx.Client(base_url = base_url,
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
                        host = url.hostname,
                        port = url.port,
                        log_level = "info",
                        ssl_cert_reqs = ssl.VerifyMode.CERT_REQUIRED,
                        ssl_ca_certs  = cfg/"known_clients",
                        ssl_certfile  = cfg/"0.crt",
                        ssl_keyfile   = cfg/"0.key",
                        ssl_keyfile_password = get_passwd,
                        http = "h11")
        else:
            raise ValueError(f"Unsupported URL scheme: {url.scheme}")
