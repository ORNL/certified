from pathlib import Path
import time
import os

import pytest
from typer.testing import CliRunner
import httpx
from cryptography import x509

from certified import Certified
from certified.test import child_process
from certified.certified import app
from certified.message import app as msg
from certified.layout import check_config
from certified.blob import Blob

runner = CliRunner()

def test_intro(tmp_path : Path) -> None:
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

    # Cannot introduce my own CA (would be a self-signature).
    result = runner.invoke(app, ["introduce", str(srv/"CA.crt"),
                                 "--config", str(srv)
                                 ])
    assert result.exit_code == 1
    assert isinstance(result.exception, AssertionError)

    result = runner.invoke(app, ["introduce", str(cli/"id.crt"),
                                 "--config", str(srv)
                                 ])
    print(result.stdout)
    assert result.exit_code == 0
    intro = result.stdout
    assert "-----BEGIN CERTIFICATE-----" in intro
    assert "-----END CERTIFICATE-----" in intro

    # note - we need to add the server's certificate to the client
    srv_ca = x509.load_pem_x509_certificate((srv/"CA.crt").read_bytes())
    Certified(cli).add_server("test", srv_ca)

    # Phase 2 - run the server without and with the introduction.
    def run_echo():
        runner.invoke(app, ["serve", "examples.echo:app",
                              "https://127.0.0.1:8312",
                              "--config", str(srv)
                           ])
    with child_process(run_echo):
        connected = False
        for i in range(200):
            time.sleep(0.01)
            try:
                result = runner.invoke(msg, [
                            "https://127.0.0.1:8312/echo/123",
                            "--config", str(cli)])
                if result.exit_code == 0:
                    break
                # This error indicates SSL handshake failed.
                if isinstance(result.exception, httpx.RemoteProtocolError):
                    break
            except httpx.ConnectError:
                continue
        assert not connected, "Connection should not succeed."

    assert result.exit_code == 1
    assert isinstance(result.exception, httpx.RemoteProtocolError)

    # Now create and add as a client explicitly.
    #
    # doesn't work -- (would, but client doesn't present this certificate)
    result = runner.invoke(app, ["introduce", str(cli/"id.crt"),
                                 "--add-client", "david",
                                 "--config", str(srv)
                                ])
    assert result.exit_code == 0
    # overwrite ID - this works, but don't do this.
    os.rename(cli/"id.crt", cli/"id1.crt")
    Blob.read(srv/"known_clients"/"david.crt").write(cli/"id.crt")

    # doesn't work -- id is signed by an unknown entity.
    # Blob.read(cli/"id.crt").write(srv/"known_clients"/"david.crt")
    # does work
    #Blob.read(cli/"CA.crt").write(srv/"known_clients"/"david.crt")
    assert "-----BEGIN CERTIFICATE-----" in \
                (srv/"known_clients"/"david.crt").read_text()

    with child_process(run_echo):
        for i in range(200):
            time.sleep(0.01)
            try:
                result = runner.invoke(msg, [
                            "https://127.0.0.1:8312/echo/123",
                            "--config", str(cli)])
                if result.exit_code == 0:
                    break
            except httpx.ConnectError:
                continue
        print(f"Server returned: {result.exit_code}")
        print(f"    {result.stdout}")
        assert result.exit_code == 0, f"Connection should succeed but found {result.exception}"
        assert result.stdout.strip() == '{"message":"123"}'
