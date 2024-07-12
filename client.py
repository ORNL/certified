import ssl # python builtin library

import httpx

#context = ssl.create_default_context()
#context.load_verify_locations(cafile="/tmp/client.pem")
#context.load_cert_chain(cert)

# cert = ("path/to/client.pem") # if pem includes private key
#cert = ("cert.pem")
cert = ("cert.pem", "cert.key")
#cert = ("path/to/client.pem", "path/to/client.key", "password") # if key is password-protected
context = httpx.create_ssl_context(cert=cert, verify="ca_root.pem")
# To setup logging for all generated keys (e.g. session symmetric keys):
# context.keylog_filename = os.environ.get("SSLKEYLOGFILE", None)

headers = {'user-agent': 'my-app/0.0.1'}

# see also httpx.AsyncClient
with httpx.Client(base_url='https://127.0.0.1:8000',
                  headers=headers,
                  verify=context) as client:
    r = client.get('/')
    print(r.json())

