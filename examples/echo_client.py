from certified import Certified
import httpx

cert = Certified()

headers = { "user-agent": "my-app/0.0.1",
            "Accept": "application/json" }

with cert.Client(base_url="https://127.0.0.1:8000",
                  headers=headers) as cli:
    resp = cli.get("echo/Hello world!")
    assert resp.status_code == httpx.codes.OK
    print( resp.json() )
