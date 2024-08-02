# Generate an identity and an initial configuration

TODO - should be just:

    certified init name@my.org

Generate a root certificate:
    python3 new_ca.py

Create a signed server and client certificate with it:
    python3 sign_cert.py -o server
    python3 sign_cert.py -i me@localhost -o client

Explanation -- the second command creates a cert.pem and cert.key
file which attests that the CA knows the identity listed in cert.pem.
The cert.key file is used during a TLS socket handshake to prove
that the identity in cert.pem belongs to them.

# Run an API Client

HTTPS already includes support for custom server authentication
and providing the server with your client certificate.

To use it with the `curl` tool, the command is:

    curl --cacert ca_root.pem --key client.key --cert client.pem \
         -H "Accept: application/json" \
         https://my-api.org:8000

    curl --cacert ca_root.pem --key client.key --cert client.pem \
         -H "Accept: application/json" \
         -H "Content-Type: application/json" \
         -X POST --data '{"message":"hello"}' \
         https://my-api.org:8000/notes

The certified package makes this easy programmatically
using the `certified.APIClient` class.

This context is an `httpx.Client` that bakes in the
appropriate client and server certificates so that
both sides can mutually authenticate one another.

An example:

    import certified

    cert = certified.Config.load()
    with cert.client("https://my-api.org:8000") as api:
        r = api.get("/")
        assert r.status_code == 200, "Read error!"
        print(r.json())

        r = api.post("/notes", json={"message": "hello"})
        assert r.status_code == 200, "Post error!"
        print(r.json())


# Run an API Server

To run an API server, create an ASGI webserver application
class (e.g. using `app = FastAPI()` inside `my_api/server.py`),
and then start it with:

    certified start my_api.server:app [additional options]


This uses uvicorn internally and is equivalent to running:

    uvicorn --ssl-keyfile server.key --ssl-certfile server.pem \
            --ssl-cert-reqs 2 --ssl-ca-certs ca_root.pem \
            --host <ip_from_config> --port <port_from_config> \
            my_api.server:app [additional options]

where `--ssl-cert-reqs 2` is the magic argument needed to ensure clients
authenticate with TLS, and the other keys are created from pem-encoding
data from your server's `certified.json` config file.

We actually implement this internally with uvicorn's
[programmatic API](https://www.uvicorn.org/deployment/#running-programmatically).

    import certified

    cert = certified.Config.load()
    cert.serve("my_api.server:app")

    # ... calls uvicorn.run("my_api.server:app", host="127.0.0.1", port=5000, log_level="info")
