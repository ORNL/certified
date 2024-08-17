import sys
import pytest
import time

import httpx

from certified.test import child_process
from certified import Certified, encode

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
    name = encode.org_name("My Company", "My Division")
    name2 = encode.org_name("My Company", "My Division", "mycompany.com")
    san  = encode.SAN(hosts=["localhost", "127.0.0.1"])

    cert = Certified.new(name, name2, san, tmp_path)
    with pytest.raises(ValueError):
        cert.serve(app, "127.0.0.1:5001")
    with pytest.raises(ValueError):
        cert.serve(app, "tcp://127.0.0.1")
    with pytest.raises(AssertionError):
        cert.serve(app, "https://127.0.0.1")
    with child_process(cert.serve, app, "https://127.0.0.1:5002"):
        connected = False
        returned  = False
        for i in range(200):
            time.sleep(0.01)
            try:
                with cert.Client("https://127.0.0.1:5002") as cl:
                    connected = True
                    r = cl.get("/test_path")
                    print("Get returns.")
                returned = True
                assert r.status_code == 200
                print(r.text())
                break
            #except httpx.RemoteProtocolError:
            #    break
            except httpx.ConnectError:
                continue
        assert connected, "Connection did not succeed."
        assert returned,  "No response returned by server."
