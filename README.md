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

or

    curl --cacert ca_root.pem --key client.key --cert client.pem https://127.0.0.1:8000/


# References

[x509]: https://cryptography.io/en/latest/x509/tutorial/#creating-a-certificate-signing-request-csr "Python x509 Cryptography HOWTO"
[openssl]: https://x509errors.org/guides/openssl "OpenSSL: TLS Guide" -- building a custom validator in C
[mtls]: https://www.golinuxcloud.com/mutual-tls-authentication-mtls/ "Mutual TLS"
[exts]: https://www.golinuxcloud.com/add-x509-extensions-to-certificate-openssl/ "Adding Extensions to x509"
[globus]: https://globus.stanford.edu/security.html

## more on custom attributes using openssl command

https://stackoverflow.com/questions/36007663/how-to-add-custom-field-to-certificate-using-openssl
https://stackoverflow.com/questions/17089889/openssl-x509v3-extended-key-usage -- config. file attributes
https://superuser.com/questions/947061/openssl-unable-to-find-distinguished-name-in-config/1118045 -- use a complete config
