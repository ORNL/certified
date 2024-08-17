# How-To Recipes for the Impatient

## Generate a new identity

Every configuration directory corresponds to a unique
identity.  You should maintain separate directories
for each person and each microservice.

Generate a certificate for a personal identity using,

    certified init 'First Last' --email name@my.org \
              --config $HOME/etc/certified

Generate a certificate for a server or microservice using,

    certified init --org 'My Company' --division 'My Org Unit' \
                   --host 'my-api.org' --host 'localhost' \
                   --email 'name@my-api.org' \
                   --config $VIRTUAL_ENV/etc/certified

Note these are stored in different places because they
represent different entities.


## Link your identity to a microservice

To successfully connect to a service, the service must
be able to authenticate your identity.  It does this
by checking your certificate has been issued by a
principle that it trusts.

To configure your service to trust you as a principle,
use

    cp $HOME/etc/certified/CA.crt \
       $VIRTUAL_ENV/etc/certified/trusted_clients/$USER.crt

According to the [configuration specification](keys.md),
this will setup the server to be able to talk to all
entities that you sign.  Note that your personal
identity has already been signed by you.

In order to introduce someone else to your server, you
can sign their identity card,

    certified introduce /home/other_user/etc/certified/0.crt \
              --scope user \
              --config $HOME/etc/certified \
              >/home/other_user/etc/certified/0/$USER.crt 


Of course, UNIX permissions don't allow doing this directly,
but the basic idea is the same.  Both the other user's `0.crt`
file and your returned signature (`crt` file) are public
documents, and can be exchanged in the open -- for example
by email or via posting to github.

That user must also setup your server as a trusted service,

    cp $VIRTUAL_ENV/etc/certified/0.crt \
       $HOME/etc/certified/trusted_servers/service_name.crt

When that user wants to access the microservice at `$VIRTUAL_ENV`,
they can now do so.  Note that you should not generally authorize
resource usage from your production services.
That should be left up to signed tokens, which can control
authorization much more precisely.

Technical explanation: the user access your microservice
using the combination of,

  * Your `$VIRTUAL_ENV/etc/certified/0.crt` (cacert / trust root)
  * Your `0/$USER.crt` (certificate chain)
  * Their `0.key` (private key)

All three ingredients are used in a TLS socket handshake to
mutually authenticate the client and server to one another.

## Run an API Client

HTTPS already includes support for custom server authentication
and providing the server with your client certificate.

To use it with the `curl` tool, the command is:

    curl --capath $cfg/trusted_servers \
         --cert $cfg/0/chain_of_trust.crt --key $cfg/0.key \
         -H "Accept: application/json" \
         https://my-api.org:8000

    curl --capath $cfg/trusted_servers \
         --cert $cfg/0/chain_of_trust.crt --key $cfg/0.key \
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

    from certified import Certified

    cert = Certified()
    with cert.client("https://my-api.org:8000") as api:
        r = api.get("/")
        assert r.status_code == 200, "Read error!"
        print(r.json())

        r = api.post("/notes", json={"message": "hello"})
        assert r.status_code == 200, "Post error!"
        print(r.json())


## Run an API Server

To run an API server, create an ASGI webserver application
class (e.g. using `app = FastAPI()` inside `my_api/server.py`),
and then start it with:

    certified serve my_api.server:app [additional options]


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
    cert.serve("my_api.server:app", "https://127.0.0.1:5000")

    # ... calls uvicorn.run("my_api.server:app", host="127.0.0.1", port=5000, log_level="info")
