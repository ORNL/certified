from typing import Optional
import ssl
from functools import wraps

import pytest

from certified import CA, LeafCert, encode, verify
from sock_test import child_server

def ssl_ify(client_or_server : str):
    is_client = client_or_server == "client"
    def close(fn):
        @wraps(fn)
        def wrap(sock, *args,
                 cert: LeafCert  = None,
                 trust_root: str = "",
                 remote_name: Optional[str]=None):
            # For a full asyncio example, see:
            # https://gist.github.com/zapstar/a7035795483753f7b71a542559afa83f
            if is_client:
                ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ssl_ctx.verify_mode = ssl.VerifyMode.CERT_REQUIRED
            else:
                ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ssl_ctx.options |= ssl.OP_SINGLE_DH_USE
                ssl_ctx.options |= ssl.OP_SINGLE_ECDH_USE
                ssl_ctx.verify_mode = ssl.VerifyMode.CERT_REQUIRED
            ssl_ctx.options |= ssl.OP_NO_TLSv1
            ssl_ctx.options |= ssl.OP_NO_TLSv1_1

            cert.configure_cert(ssl_ctx) # runs load_cert_chain
            #ssl_ctx.load_cert_chain('client_cert.pem', keyfile='client_key.pem')
            ssl_ctx.load_verify_locations(trust_root)

            if remote_name is None:
                ssl_ctx.check_hostname = False

            #ssl_ctx.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384')

            with ssl_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                print(f"SSL {client_or_server} connected, version " + str(ssock.version()))
                return fn(ssock, *args)
        return wrap
    return close

@ssl_ify("client")
def client(sock, data):
        print('Sending: {}'.format(data))
        sock.send(data.encode())
        rep = sock.recv(128)
        print('Received: {}'.format(rep))

@ssl_ify("server")
def echo_server(sock):
    addr = sock.get_extra_info('peername')
    print('Connection established with {}'.format(addr))
    while True:
        msg = sock.recv(1024)
        sock.sendall(msg)

def test_cxn():
    name = encode.name("Test Org.", "Testing Unit")
    ca = CA.new(name)
    trust_root = ca.cert_pem.bytes().decode("ascii")
    cli_cert  = ca.issue_cert(name, encode.SAN(emails=["tim@test.org"]))
    srv_cert  = ca.issue_cert(name, encode.SAN(hosts=["localhost"]))

    def ssl_echo(sock):
        echo_server(sock,
                    cert=srv_crt,
                    trust_root=trust_root,
                    remote_name=None)
    with child_server(ssl_echo) as sock:
        client(sock, "Hello", 
                    cert=cli_cert,
                    trust_root=trust_root,
                    remote_name=None)

@pytest.mark.skipif(True, reason="Overly restrictive verification")
def test_ca():
    name = encode.name("My Company", "My Division")
    san = encode.SAN(hosts=["example.com"])
    crt = CA.new(name, san)

    ee = crt.issue_cert(name, san)

    n = verify.by_chain("example.com", ee.certificate, crt.certificate)
    assert n == 0

