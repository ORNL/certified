import sys
import pytest
import time

import httpx

from certified.test import child_process
from certified import Identity, encode

async def app(scope, receive, send):
    print(f"scope: " + str(scope))
    if scope["type"] == "lifecycle":
        return ""
    msg = await receive()
    await send({ "type": "http.response.start",
                 "status": 200,
                 "headers": [[b"content-type", b"text/plain"],],
        })
    await send({
            "type": "http.response.body",
            "body": scope.raw_path,
            "more_body": False,
        })

def test_start(tmp_path):
    name = encode.org_name("My Company", "My Division", "mycompany.com")
    san  = encode.SAN(hosts=["localhost", "127.0.0.1"])

    cert = Identity.new(name, san, tmp_path)
    with pytest.raises(AssertionError):
        cert.serve(app, "127.0.0.1:5001")
    with pytest.raises(ValueError):
        cert.serve(app, "tcp://127.0.0.1")
    with child_process(cert.serve, app, "tcp://127.0.0.1:5002"):
        connected = False
        for i in range(200):
            time.sleep(0.01)
            try:
                with cert.Client("https://127.0.0.1:5002") as cl:
                    connected = True
                    r = cl.get("/test_path")
                    print("Get returns.")
                assert r.status_code == 200
                print(r.text())
                break
            #except httpx.RemoteProtocolError:
            #    break
            except httpx.ConnectError:
                continue
        assert connected, "No connection succeeded in 2 sec."
