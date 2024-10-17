from typing import Optional
from pathlib import Path
import ssl
from functools import wraps

from .ca import LeafCert

def configure_capath(ssl_ctx : ssl.SSLContext, capath : Path) -> None:
    data = "\n".join(f.read_text() \
                        for f in capath.iterdir() \
                        if f.suffix in [".crt", ".pem"]
                    )
    # Use cadata instead
    ssl_ctx.load_verify_locations(cadata=data)

def ssl_context(is_client: bool,
                require_client_cert: bool = True,
                allow_TLS_1_2: bool = False) -> ssl.SSLContext:
    if is_client:
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_ctx.verify_mode = ssl.VerifyMode.CERT_REQUIRED
    else:
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        if require_client_cert: # mTLS
            ssl_ctx.verify_mode = ssl.VerifyMode.CERT_REQUIRED
        else:
            ssl_ctx.verify_mode = ssl.VerifyMode.CERT_OPTIONAL
        # mostly default since 3.6, but set explicitly anyway
        #ssl_ctx.options |= ssl.OP_SINGLE_DH_USE
        #ssl_ctx.options |= ssl.OP_SINGLE_ECDH_USE
        ssl_ctx.options |= ssl.OP_NO_RENEGOTIATION
        ssl_ctx.options |= ssl.OP_NO_COMPRESSION
    try:
        # Accept certificates when an ancestor shows up in the trust store.
        ssl_ctx.options |= getattr(ssl, 'VERIFY_X509_PARTIAL_CHAIN')
    except AttributeError:
        pass
    if allow_TLS_1_2:
        ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    else:
        ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ssl_ctx

def ssl_ify(client_or_server : str):
    is_client = client_or_server == "client"
    def close(fn):
        @wraps(fn)
        def wrap(sock, *args,
                 cert: LeafCert,
                 trust_root: str,
                 remote_name: Optional[str] = None):
            # trust_root should be the ascii-decoded
            # contents of the trust root's PEM-format
            # certificate.
            #
            # For a full asyncio example, see:
            # https://gist.github.com/zapstar/a7035795483753f7b71a542559afa83f

            ssl_ctx = ssl_context(is_client)

            server_hostname : Optional[str] = None
            if is_client:
                server_hostname = remote_name

            cert.configure_cert(ssl_ctx) # runs load_cert_chain
            #ssl_ctx.load_cert_chain('client_cert.pem', keyfile='client_key.pem')
            ssl_ctx.load_verify_locations(cadata=trust_root)

            if remote_name is None:
                ssl_ctx.check_hostname = False

            #ssl_ctx.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384')
            with ssl_ctx.wrap_socket(sock,
                    server_side = not is_client,
                    server_hostname = server_hostname,
                    do_handshake_on_connect=False) as ssock:
                # server_hostname=remote_name
                print(f"SSL {client_or_server} connecting, version " + str(ssock.version()))
                ssock.do_handshake()
                peer = ssock.getpeercert()
                print(f"SSL Peer = {str(peer)}")
                return fn(ssock, *args)
        return wrap
    return close
