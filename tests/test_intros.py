from typing import Tuple
from pathlib import Path
import time
import os
import json

import pytest
from typer.testing import CliRunner
import httpx
from cryptography import x509

from certified import Certified
from certified.encode import rfc4514name
from certified.test import child_process
from certified.certified import app
from certified.message import app as msg
from certified.layout import check_config
from certified.blob import Blob
from certified.models import TrustedService
from certified.serial import cert_to_b64, pem_to_cert, b64_to_cert

runner = CliRunner()

def run_echo(srv : Path, port : int) -> None:
    runner.invoke(app, ["serve", "examples.echo:app",
                          f"https://127.0.0.1:{port}",
                          "--config", str(srv)
                       ])

def can_connect(cli : Path, srv : Path, host : str, port : int) -> bool:
    """ Check whether the client can connect to
        the server https://{host}:{port}.

        Note -- the server always runs at 127.0.0.1,
        but the host name may be significant for
        the client to look up the server as a KnownService.

        If connection succeeds, return True.
        If connection has a handshake error (due
        to auth. failed), return False.

        Otherwise, raises an error.
    """
    url = f"https://{host}:{port}/echo/123"
    with child_process(run_echo, srv, port):
        connected = False
        for i in range(200):
            time.sleep(0.01)

            result = runner.invoke(msg, [url, "--config", str(cli)])
            if result.exit_code == 0:
                connected = True
                break
            # This error indicates SSL handshake failed.
            if isinstance(result.exception, httpx.RemoteProtocolError):
                print("RemoteProtocolError =====================")
                print(result.exception)
                break
            elif isinstance(result.exception, TimeoutError):
                continue
            elif isinstance(result.exception, httpx.ConnectError):
                e = str(result.exception)
                if "Connection refused" in e or \
                   "Temporary failure in name resolution" in e:
                    # server not yet ready.
                    continue
                elif "CERTIFICATE_VERIFY_FAILED" in str(result.exception):
                    break
                raise ValueError(result.exception)
            else:
                raise ValueError(result.exception)
        else:
            assert False, f"Failed to connect to server {url}: {result.exception}"

    if connected:
        assert result.stdout.strip() == '{"message":"123"}', \
                "Connected, but server sent bad result."
        return True
    if result.exit_code != 1:
        # f"Connection should succeed but found {result.exception}"
        print(f"Server returned: {result.exit_code}")
        print(f"    {result.stdout}")
    assert result.exit_code == 1
    return False

def create_pair(tmp_path : Path) -> Tuple[Path,Path]:
    cli = tmp_path / "client"
    srv = tmp_path / "server"

    result = runner.invoke(app, ["init", "--config", str(cli),
                                 "David Rogers",
                                 "--email", "me@home.org"])
    assert result.exit_code == 0
    warn, err = check_config(cli)
    assert len(warn) == 0
    assert len(err) == 0

    result = runner.invoke(app, ["init", "--config", str(srv),
                                 "--org", "Fictitious Organization",
                                 "--unit", "Fraud Detection",
                                 "--host", "127.0.0.1"])
    assert result.exit_code == 0
    warn, err = check_config(srv)
    assert len(warn) == 0
    assert len(err) == 0
    return cli, srv

def test_intro_id(tmp_path : Path) -> None:
    cli, srv = create_pair(tmp_path)
    print("testing server self-connection")
    assert can_connect(srv, srv, "127.0.0.1", 8312)

    # Cannot introduce my own CA (would be a self-signature).
    result = runner.invoke(app, ["introduce", str(srv/"CA.crt"),
                                 "--config", str(srv)
                                 ])
    assert result.exit_code == 1
    # signing a CA throws a ValueError (bad path length)
    assert isinstance(result.exception, ValueError)
    # self-signature throws an AssertionError
    #assert isinstance(result.exception, AssertionError)

    # TODO: also test introduce cli/"CA.crt"
    # introduce the client -- providing them a signed
    # certificate the server will accept.
    result = runner.invoke(app, ["introduce", str(cli/"id.crt"),
                                 "--config", str(srv)
                                 ])
    print(result.stdout)
    assert result.exit_code == 0
    (tmp_path/"intro.json").write_text(result.stdout)
    intro = json.loads(result.stdout)
    signed_cert = b64_to_cert(intro["signed_cert"])
    assert isinstance(signed_cert, x509.Certificate)
    ca_cert = b64_to_cert(intro["ca_cert"])
    assert isinstance(ca_cert, x509.Certificate)
    signed_cert.verify_directly_issued_by(ca_cert)

    # add the server's certificate to the client
    srv_ca = (srv/"CA.crt").read_text() # TODO: also test "id.crt" -- which throws self-signed cert. error :_(
    srv_ca_crt = pem_to_cert(srv_ca)
    service = TrustedService(url = "127.0.0.1",
                             cert = cert_to_b64(srv_ca_crt),
                             auths = ["test_auth"])
    with pytest.raises(AssertionError):
        # bad url (parses as path for some reason)
        Certified(cli).add_service("test", service)

    xname = rfc4514name(srv_ca_crt.subject)
    service = TrustedService(url = "https://127.0.0.1",
                             cert = cert_to_b64(srv_ca_crt),
                             auths = [xname])
    Certified(cli).add_service("test", service)

    # Phase 2 - run the server without and with the introduction.
    print("testing un-intro.")
    assert not can_connect(cli, srv, "127.0.0.1", 8313)
    #time.sleep(1)

    # server known, but no appropriate signature
    result = runner.invoke(msg, [
                    f"https://test:8314/echo/123",
                    "--config", str(cli)])
    assert result.exit_code == 1
    assert isinstance(result.exception, KeyError)

    # Write the introduction
    result = runner.invoke(app, [
                    "add-intro", str(tmp_path/"intro.json"),
                    "--config", str(cli)])
    assert result.exit_code == 0
    print(f"Looking for '{xname}.crt'")
    assert (cli/"id"/f"{xname}.crt").exists()

    print("testing with-intro")
    assert can_connect(cli, srv, "test", 8314)

def test_manual_add(tmp_path : Path) -> None:
    cli, srv = create_pair(tmp_path)

    # Apparently adding client ee-certs
    # requires VERIFY_X509_PARTIAL_CHAIN
    # available in python/ssl 3.10+
    #
    # Without that, clients can't be added directly.
    result = runner.invoke(app, ["add-client", "david", str(cli/"CA.crt"),
                                 "--config", str(srv)
                                 ])
    print(result.stdout)
    assert result.exit_code == 0

    print("testing before client recognizes server")
    assert not can_connect(cli, srv, "127.0.0.1", 8323), \
            "Client should not recognize server."

    #result = runner.invoke(app, ["add-service", "test", str(cli/"id.crt"),
    #                             "--config", str(srv)
    #                            ])
    #assert result.exit_code == 1
    ## not a signing certificate [sic]
    #assert isinstance(result.exception, AssertionError)

    # FIXME: this creates a custom service, which doesn't jive...
    """
    result = runner.invoke(app, ["add-service", "test", str(srv/"id.crt"),
                                 "--config", str(cli)
                                ])
    print(result.stdout)
    assert result.exit_code == 0
    assert can_connect(cli, srv, "test", 8324)
    """

    # stupid self-signed bug.
    #(cli/"known_servers"/"test.crt").write_text(
    #        (srv/"id.crt").read_text() )
    (cli/"known_servers"/"test.crt").write_text(
            (srv/"CA.crt").read_text() )
    print("testing with client/server mutual recognition")
    assert can_connect(cli, srv, "127.0.0.1", 8324)
