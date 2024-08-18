import pytest

from certified import CA, LeafCert, encode, verify
from certified.test import child_server
from certified.wrappers import ssl_ify

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

def test_new_ca():
    name = encode.org_name("My Company", "My Division", "mycompany.com")
    CA.new(name)

def test_cxn():
    name  = encode.org_name("Test Org.", "Testing Unit")
    name2 = encode.org_name("Test Org.", "Testing Unit", pseudonym="Signing key for test org.")
    ca = CA.new(name)
    trust_root = ca.cert_pem.bytes().decode("ascii")
    cli_cert  = ca.issue_cert( encode.person_name("Tim Tester",
                                                  "tim@test.org"),
                               encode.SAN(emails=["tim@test.org"]) )
    with pytest.raises(AssertionError):
        srv_cert  = ca.issue_cert(name, encode.SAN(hosts=["localhost"]))
    srv_cert  = ca.issue_cert(name2, encode.SAN(hosts=["localhost"]))

    """ # to manually debug by calling openssl s_server
    import subprocess
    import shutil
    with ca.cert_pem.tempfile() as ca_root:
      with srv_cert.private_key_pem.tempfile() as key:
        with srv_cert.cert_chain_pems[0].tempfile() as crt:
          shutil.copyfile(ca_root, "/home/99r/ca_root.crt")
          shutil.copyfile(crt, "/home/99r/srv.crt")
          shutil.copyfile(key, "/home/99r/srv.key")

          cmd = f"openssl s_server -CAfile {ca_root} -cert {crt} -key {key}"
          process = subprocess.run(cmd, shell=True, check=True)
          # won't return if sucessful...
    """

    def ssl_echo(sock):
        print("Starting server.")
        echo_server(sock,
                    cert=srv_cert,
                    trust_root=trust_root,
                    remote_name=None)
    with child_server(ssl_echo) as sock:
        client(sock, "Hello", 
                    cert=cli_cert,
                    trust_root=trust_root,
                    remote_name=None)

def test_ca():
    name = encode.org_name("My Company", "My Division")
    name2 = encode.org_name("My Company", "Other Division")
    san = encode.SAN(hosts=["example.com"])
    crt = CA.new(name, san, key_type="secp256r1")
    ee = crt.issue_cert(name2, san, key_type="secp256r1")

    n = verify.by_chain("example.com", [ee.certificate, crt.certificate])
    assert n == 2
