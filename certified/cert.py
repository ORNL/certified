import os
import asyncio
from typing import Union, Optional, Tuple, List, Any, Dict
from urllib.parse import urlparse, urlunparse
from urllib.parse import ParseResult as URL
from contextlib import contextmanager, asynccontextmanager
from pathlib import Path, PurePosixPath
from datetime import datetime, timedelta, timezone
import ssl
import shutil
import logging
_logger = logging.getLogger(__name__)

import yaml # type: ignore[import-untyped]
from cryptography import x509
import biscuit_auth as bis

import certified.layout as layout
from .encode import (
    append_pseudonym,
    rfc4514name,
    get_is_ca,
)
from .ca import CA, LeafCert
from .wrappers import ssl_context, configure_capath
from .blob import Pstr, PWCallback, Blob
from .models import TrustedService
from .serial import pem_to_cert, cert_to_pem, b64_to_cert, cert_to_b64
from .loki import capture_logs

try:
    import uvicorn
    # https://github.com/encode/uvicorn/discussions/2307
    from uvicorn.protocols.http.h11_impl import RequestResponseCycle
    responseCycleInit = RequestResponseCycle.__init__
    def monkey_patch_response_cycle(self,*k,**kw):
        responseCycleInit(self,*k,**kw)
        self.scope['transport'] = self.transport
    RequestResponseCycle.__init__ = monkey_patch_response_cycle # type: ignore[method-assign]
except ImportError:
    uvicorn = None # type: ignore[assignment]

try:
    import aiohttp
except ImportError:
    aiohttp = None # type: ignore[assignment]
try:
    import httpx
except ImportError:
    httpx = None # type: ignore[assignment]

def replace_baseurl(url : URL, new_base : str) -> URL:
    """ Replace url's netloc with new_base,
        and prepend the path from new_base to url.path.

        Leaves all other parts of url unchanged.
    """
    new = urlparse(new_base)
    assert new.scheme == "" or new.scheme == url.scheme, "Cannot change protocol scheme."
    assert new.params   == "", "URL must not contain params"
    assert new.query    == "", "URL must not contain query"
    assert new.fragment == "", "URL must not contain fragment"

    # find host:port combination.
    host = new.hostname
    assert host is not None
    port = new.port
    if port is None:
        assert new.netloc == new.hostname, "URL's netloc must define only a hostname and optional port."
        port = url.port # keep any url port, if defined
    else:
        assert new.netloc == f"{new.hostname}:{new.port}", "URL's netloc must define only a hostname and optional port."
        assert url.port is None, "Cannot define port in both the server's url field and the server name."

    # join the two paths with new at the left.
    if new.path == "":
        new_path = url.path
    else:
        new_path = str(PurePosixPath(new.path) / url.path.lstrip("/"))
    return URL(scheme   = url.scheme,
               netloc   = f"{host}:{port}" if port else host,
               path     = new_path,
               params   = url.params,
               query    = url.query,
               fragment = url.fragment)


class Certified:
    def __init__(self, certified_config : Optional[Pstr] = None):
        self.config = layout.config(certified_config)

    def signer(self):
        return CA.load(self.config / "CA")

    def identity(self):
        return LeafCert.load(self.config / "id")

    def lookup_server(self, name) -> Optional[TrustedService]:
        """ Check if the server is known.

            If so, return the service's config.
        """
        server = self.config / "known_servers" / f"{name}.yaml"
        if not server.exists():
            return None
        with open(server, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f)
        return TrustedService.model_validate(cfg)

    def get_chain_from(self, auths : List[str]) -> Tuple[bytes, bytes]:
        """ Get a certificate chain from
            any of the signers to either "id.crt" (preferred)
            or "CA.crt" -> "id.crt" (second choice).

            Returns the appropriate end-entity certificate
            along with a concatenation of all the certificates
            in the chain.
        """
        signers = set(auths)
        if (self.config / "id").is_dir():
            for fname in (self.config / "id").iterdir():
                if fname.suffix != ".crt":
                    continue
                if fname.stem in signers:
                    # ee-cert signed directly by a signer, just return it.
                    _logger.debug("Found end-entity signature from %s", fname.name)
                    return fname.read_bytes(), b""

        if (self.config / "CA").is_dir():
            for fname in (self.config / "CA").iterdir():
                if fname.suffix != ".crt":
                    continue
                if fname.stem in signers:
                    # CA was signed by signer. Return my id.crt and the CA chain.
                    crt = (self.config / "id.crt").read_bytes()
                    _logger.debug("Found CA signature from %s", fname.name)
                    return crt, fname.read_bytes()

        raise KeyError(f"Unable to find any certificate signed from any authorizers in ({signers}).")

    def ssl_context(self,
                    is_client : bool,
                    srv : Optional[TrustedService] = None
                   ) -> ssl.SSLContext:
        if srv is not None:
            assert is_client, "Must be client to use TrustedService cfg."
        ctx = ssl_context(is_client)
        if not srv or len(srv.auths) == 0:
            _logger.debug("Will authenticate using id.crt")
            self.identity().configure_cert(ctx)
        else: # lookup any signature trusted by the server
            crt, chain = self.get_chain_from(srv.auths)
            keyfile = self.config / "id.key"
            key  = Blob.read(keyfile)
            assert key.is_secret, f"{keyfile} has compromised file permissions."
            LeafCert(crt, key.bytes(), chain_to_ca=[chain]).configure_cert(ctx)
            
        if is_client:
            if srv is None or srv.cert is None:
                configure_capath(ctx, self.config/"known_servers")
            else:
                # Use the server's specific certificate.
                _logger.debug("Requiring specific certificate for known service at %s", srv.url)
                pem = cert_to_pem( b64_to_cert(srv.cert) )
                ctx.load_verify_locations(cadata=pem)
        else:
            configure_capath(ctx, self.config/"known_clients")
        return ctx

    def add_client(self,
                   name: Pstr,
                   cert: x509.Certificate,
                   scopes: List[str] = [],
                   overwrite: bool = False) -> None:
        """ Add the certificate to `known_clients`
            with the given name.
        """
        fname = self.config / "known_clients" / f"{str(name)}.crt"
        if not overwrite and fname.exists():
            raise FileExistsError(fname)
        fname.write_text(cert_to_pem(cert))

    def add_service(self,
                    name : Pstr,
                    srv  : TrustedService,
                    overwrite:bool = False) -> None:
        """ Add the certificate to `known_servers`
            with the given info.  See `TrustedService`
            for documentation on the attributes.
        """
        parse = urlparse(srv.url)
        assert parse.netloc != "", "Service URL must define a hostname!"
        assert parse.params == "", "Service URL must not use params."
        assert parse.query  == "", "Service URL must not use query."
        assert parse.fragment == "", "Service URL must not use fragment."

        fname = self.config / "known_servers" / f"{str(name)}.yaml"
        if not overwrite and fname.exists():
            raise FileExistsError(fname)
        fname.write_text( yaml.dump( srv.model_dump() ) )

    def add_identity(self,
                     signed_cert: x509.Certificate,
                     ca_cert: x509.Certificate,
                     overwrite: bool = False) -> None:
        """ Add the signed certificate to the `id/` subdirectory.
        Params:
            signed_cert: identity to add (to send to servers who recognize it)
            ca_cert: certificate that signed this identity
                     (will be used to name the signed identity)

        Returns: None

        Raises:
            ValueError: If the issuer name on the certificate does not match
                        the subject name of the issuer or the signature
                        algorithm is unsupported.
            TypeError: If the issuer does not have a supported public key
                       type.
            cryptography.exceptions.InvalidSignature: If the signature fails
                       to verify.
        """
        assert not get_is_ca(signed_cert), "Cannot use this ca certificate as a client identity."

        # check that the ca_cert actually issued this certificate
        signed_cert.verify_directly_issued_by(ca_cert)

        xname = rfc4514name(ca_cert.subject)

        (self.config / "id").mkdir(exist_ok=True, parents=True)
        fname = self.config / "id" / f"{xname}.crt"
        if not overwrite and fname.exists():
            raise FileExistsError(fname)
        fname.write_text(cert_to_pem(signed_cert))

    def lookup_public_key(self, kid : int) -> bis.PublicKey:
        # FIXME: use key serial numbers
        pubkey = self.signer().pubkey.public_bytes_raw()
        #if kid is None:
        #    return bis.PublicKey.from_bytes( pubkey )
        return bis.PublicKey.from_bytes( pubkey )

    #def biscuit(self, token : str) -> bis.Biscuit:
    #    return bis.Biscuit.from_base64(token, self.lookup_public_key)

    @classmethod
    def new(cls,
            name : x509.Name,
            san : x509.SubjectAlternativeName,
            certified_config : Optional[Pstr] = None,
            overwrite : bool = False,
           ) -> "Certified":
        """ Create a new CA and identity certificate
        
        Args:
          name: the distinguished name for the signing key
          san:   subject alternate name fields for the entity certificate
          certified_config: base directory to output the new identity
          overwrite: if True, any existing files will be deleted first
        """
        ca    = CA.new(append_pseudonym(name, "Signing Certificate"))
        ident = ca.leaf_cert(name, san)

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
        ident.save(cfg / "id", False)

        (cfg/"known_servers").mkdir()
        (cfg/"known_clients").mkdir()
        shutil.copy(cfg/"CA.crt", cfg/"known_servers"/"self.crt")
        shutil.copy(cfg/"CA.crt", cfg/"known_clients"/"self.crt")
        return cls(cfg)

    @asynccontextmanager
    async def ClientSession(self, base_url: str = "", **kws):
        """ Create an aiohttp.ClientSession context
            that includes the current identity within
            its ssl context (connector=...).
        """
        assert aiohttp is not None, "aiohttp is not available."

        # Check whether this server corresponds to a known host.
        url = urlparse(base_url)
        assert url.port is None \
                or url.netloc == f"{url.hostname}:{url.port}", "URL's netloc must define only a hostname and port."

        srv = self.lookup_server(url.hostname)
        if srv:
            url = replace_baseurl(url, srv.url)

        new_base = urlunparse(url)
        if srv:
            _logger.debug("Replaced %s with %s", base_url, new_base)

        ssl_ctx = self.ssl_context(True, srv)
        #conn = aiohttp.TCPConnector(ssl_context=ssl_ctx)
        conn = aiohttp.TCPConnector(ssl=ssl_ctx)
        async with aiohttp.ClientSession(base_url = new_base,
                                         connector = conn,
                                         **kws) as client:
            yield client

    @contextmanager
    def Client(self, base_url : str = "", headers : Dict[str,str] = {}):
        """ Create an httpx.Client context
            that includes the current identity within
            its ssl context.
        """
        assert httpx is not None, "httpx is not available."

        # Check whether this server corresponds to
        # a known host.
        url = urlparse(base_url)
        assert url.port is None \
                or url.netloc == f"{url.hostname}:{url.port}", "URL's netloc must define only a hostname and port."

        srv = self.lookup_server(url.hostname)
        if srv:
            url = replace_baseurl(url, srv.url)

        new_base = urlunparse(url)
        if srv:
            _logger.debug("Replaced %s with %s", base_url, new_base)

        ssl_ctx = self.ssl_context(True, srv)
        with httpx.Client(base_url = new_base,
                          headers = headers,
                          verify = ssl_ctx) as client:
            yield client

    def serve(self,
              app : Any,
              url_str : str,
              loki : Optional[Pstr] = None,
              get_passwd : PWCallback = None) -> None:
        cfg = self.config
        url = urlparse(url_str)

        if url.scheme == "https":
            assert url.hostname is not None, "URL must define a hostname."
            assert url.port is not None, "URL must define a port."
            assert url.netloc == f"{url.hostname}:{url.port}", "URL's netloc must define only a hostname and port."
            assert url.path == "", "Cannot serve a sub-path."
            assert url.params == "", "Cannot handle URL parameters."
            assert url.query == "", "Cannot serve specific query."
            assert url.fragment == "", "Cannot serve specific fragment"

            assert uvicorn is not None, "uvicorn is not available."

            config = uvicorn.Config(
                        app,
                        host = url.hostname,
                        port = url.port,
                        log_level = "info",
                        #ssl_cert_reqs = ssl.VerifyMode.CERT_REQUIRED,
                        #ssl_ca_certs  = cfg/"known_clients", # type: ignore[arg-type]
                        #ssl_certfile  = cfg/"id.crt",
                        #ssl_keyfile   = cfg/"id.key", # type: ignore[arg-type]
                        #ssl_keyfile_password = get_passwd, # type: ignore[arg-type]
                        http = "h11")


            config.load() # https://github.com/encode/uvicorn/discussions/2339
            _logger.debug("Using Certified's custom ssl context.")
            config.ssl = self.ssl_context(False)

            capture_logs(str(app), loki)
            server = uvicorn.Server(config)
            asyncio.run( server.serve() )
        else:
            raise ValueError(f"Unsupported URL scheme: {url.scheme}")
