# Usage

Generate a root certificate:
    python3 new_ca.py

Create a signed server and client certificate with it:
    python3 sign_cert.py -o server
    python3 sign_cert.py -i me@localhost -o client

Explanation -- the second command creates a cert.pem and cert.key
file which attests that the CA knows the identity listed in cert.pem.
The cert.key file is used during a TLS socket handshake to prove
that the identity in cert.pem belongs to them.

Start a test server using:

```
uvicorn --ssl-keyfile server.key --ssl-certfile server.pem \
        --ssl-cert-reqs 1 --ssl-ca-certs ca_root.pem \
        server:app
```

Securely query the server with:

    python3 client.py
