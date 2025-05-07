# Command-line interface to certified

import os, shutil
import asyncio
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Union, Dict
from typing_extensions import Annotated
from urllib.parse import urlsplit, urlunsplit
import binascii

import logging
_logger = logging.getLogger(__name__)

import typer

import certified.encode as encode
import certified.layout as layout
from .blob import PublicBlob
from .cert import Certified
from .cert_info import CertInfo
from .cert_base import load_pem_private_key
from .models import TrustedService
from .serial import cert_to_b64, b64_to_cert, cert_to_pem

from cryptography import x509

#from actor_api.grant import Grant
#from actor_api.validation import signGrant, validateGrant
#from actor_api.crypto import gen_key, gen_keypair, get_verifykey, get_pubkey
#from actor_api.actor_test import cli_srv, srv_sign

app = typer.Typer()


Email = Annotated[ List[str],
                   typer.Option(help="email addresses",
                        rich_help_panel="Example: example@example.org"
                 ) ]
Hostname = Annotated[ List[str],
                      typer.Option(rich_help_panel="host names",
                        help="""Examples:
    - "*.example.org"
    - "example.org"
    - "éxamplë.org"
    - "xn--xampl-9rat.org"
    - "127.0.0.1"
    - "::1"
    - "10.0.0.0/8"
    - "2001::/16"
""") ]
URI = Annotated[ List[str],
                 typer.Option(rich_help_panel="uniform resource identifiers",
                        help="Example: https://datatracker.ietf.org/doc/html/rfc3986#section-1.1.2"
               ) ]
Config = Annotated[Optional[Path], typer.Option(
                        help="Config file path [default $VIRTUAL_ENV/etc/certified].") ]

def load_certfile(crt : Path) -> x509.Certificate:
    pem_data = crt.read_bytes()
    asc_data = pem_data.decode('ascii').strip()
    if asc_data.startswith('-----BEGIN CERTIFICATE-----\n'):
        return x509.load_pem_x509_certificate(pem_data)
    else:
        return b64_to_cert(asc_data)

@app.command()
def init(name: Annotated[
                    Optional[str],
                    typer.Argument(rich_help_panel="Person Name",
                        help="""Note, name parsing into given and surnames
and generations, etc. is not supported.

Examples:
    - Timothy T. Tester
""")
                ] = None,
         org: Annotated[
                    Optional[str],
                    typer.Option(rich_help_panel="Organization Name",
                        help="""If specified, unit must also be present and name cannot be present.
Example: 'Certificate Lab, Inc.'"
""")
                ] = None,
         unit: Annotated[
                    Optional[str],
                    typer.Option(rich_help_panel="Organization Unit",
                        help="""If specified, org must also be present and name cannot be present.
Example: 'Computing Directorate'
""")
                ] = None,
         uid: Annotated[
                    Optional[str],
                    typer.Option(help="System user name")
             ] = None,
         domain: Annotated[
                    str,
                    typer.Option(help="Domain components (.-separated)")
             ] = "",
         country: Optional[str] = None,
         state: Optional[str] = None,
         city: Optional[str] = None,
         email: Email = [],
         host: Hostname = [],
         uri: URI = [],
         overwrite: Annotated[bool, typer.Option(
                        help="Overwrite existing config.")
                    ] = False,
         config : Config = None) -> int:
    """
    Create a new signing and end-entity ID.
    """

    # Validate arguments
    if org or unit:
        assert unit, "If org is defined, unit must also be defined."
        assert org, "If unit is defined, org must also be defined."
        #assert name is None, "If org is defined, name must not be defined."
        assert uid is None, "If org is defined, uid must not be defined."
        xname = encode.org_name(org, unit,
                                domain=domain.split('.'),
                                location=(country,state,city))
    elif name:
        assert org is None, "If name is defined, org must not be defined."
        assert unit is None, "If name is defined, unit must not be defined."
        xname = encode.person_name(name, uname=uid,
                                   domain=domain.split('.'),
                                   location=(country,state,city))
    else:
        raise AssertionError("Name or org must be provided.")
    if sum(map(len, [email, host, uri])) > 0:
        san  = encode.SAN(email, host, uri)
    else:
        raise ValueError("Host, Email, or URI must also be provided.")

    cert = Certified.new(xname, san, config, overwrite)
    print(f"Generated new config for {encode.rfc4514name(xname)} at {cert.config}.")
    return 0

@app.command()
def add_client(name : Annotated[
                        str,
                        typer.Argument(help="Client's name.")
                    ],
               crt : Annotated[
                        Path,
                        typer.Argument(help="Client's certificate (PEM or b64-DER).")
                    ],
               scopes : Annotated[
                        str,
                        typer.Argument(help="Whitespace-separated list of allowed scopes.")
                    ] = "",
               overwrite: Annotated[bool, typer.Option(
                        help="Overwrite existing client.")
                    ] = False,
               config : Config = None):
    """
    Add the client directly to your `known_clients` list.

    Note that this routine doesn't work for end-entities in practice
    because x509 validation rules don't allow self-signed
    certificates to be clients.

    However, you can add a self-signed "root" this way
    and trust all certificates granted through it.
    """

    cert = Certified(config)
    c = load_certfile(crt)
    # validate c is a signing cert (otherwise TLS balks)
    #assert encode.get_is_ca(c), "TLS doesn't allow trusting end-identies directly [sic]."
    # TODO: check for ideas at https://hg.python.org/cpython/rev/2afe5413d7af

    cert.add_client(name, c, scopes.split(), overwrite)

    return 0

@app.command()
def add_service(name : Annotated[
                        str,
                        typer.Argument(help="Service's hostname[:port][/path-prefix].")
                    ],
               crt : Annotated[
                        Path,
                        typer.Argument(help="Service's public signing certificate (PEM or b64-DER or json with 'ca-root').")
                    ],
               auth : Annotated[
                        List[str],
                        typer.Option(help="rfc4514 name of an authorizor whose signature would be recognized for authenticating to this server.")
                    ] = [],
               overwrite: Annotated[bool, typer.Option(
                        help="Overwrite existing server.")
                    ] = False,
               config : Config = None) -> int:
    """
    Add the service directly to your `known_servers` list.
    """

    cert = Certified(config)

    try:
        c = load_certfile(crt)
    except binascii.Error as e:
        with open(crt, "r", encoding='utf-8') as f:
            data = json.load(f)
        c = b64_to_cert(data["ca_cert"])

    # validate c is a signing cert (otherwise TLS balks)
    #assert encode.get_is_ca(c), "TLS doesn't allow trusting end-identies directly [sic]."

    xname = encode.rfc4514name(c.subject)
    if xname not in auth: # services generally trust thes'selvs
        auth.append(xname) 
    # TODO: validate name is host[:port] (i.e. that https://{name} works)

    srv = TrustedService(
              url = f"https://{name}",
              cert = cert_to_b64(c),
              auths = auth
          )
    cert.add_service(name, srv, overwrite)
    return 0

@app.command()
def introduce(crt: Annotated[
                       Path,
                       typer.Argument(help="Subject's certificate.")
                   ],
              config: Config = None) -> int:
    """
    Write an introduction for the subject named by the
    certificate above.  Do not use this function unless
    you have checked both of the following:

    1. The certificate is actually held by the subject and
       not someone else pretending to be the subject.

    2. The subject will maintain the secrecy of their
       private key, and not copy it anywhere.

    If either of those are false, your introductions are no
    longer trustworthy, and you'll need to create a new
    identity!

    To use this introduction, the subject will need to run
    `certified add-intro`.  That command will place
    your response in their config. as `id/<your_name>.crt`
    or `CA/<your_name>.crt` (depending on which certificate
    was signed), as well as listing <your_name>
    within one of their `known_server/<server_name>.yaml` files.
    """

    cert = Certified(config)

    pem_data = crt.read_bytes()
    csr : Union[x509.Certificate, x509.CertificateSigningRequest]
    try:
        csr = x509.load_pem_x509_csr(pem_data)
    except ValueError:
        try:
            csr = x509.load_pem_x509_certificate(pem_data)
        except ValueError:
            csr = b64_to_cert(pem_data.strip().decode('ascii'))
    info = CertInfo.load(csr)
    signer = cert.signer()
    signed = signer.issue_cert(info)
    #print( PublicBlob(signed).bytes().decode("utf-8").rstrip() )
    intro = { "signed_cert": cert_to_b64(signed),
              "ca_cert": cert_to_b64(signer.certificate)
            }
    print( json.dumps(intro, indent=2) )
    return 0

@app.command()
def add_intro(signature : Annotated[
                        Path,
                        typer.Argument(help='json signature response containing both "signed_cert" and "ca_cert".')
                    ],
               overwrite: Annotated[bool, typer.Option(
                        help="Overwrite existing authorization?")
                    ] = False,
               config : Config = None) -> int:
    """ Add an introduction to use when authenticating
    to servers that trust this signer.
    """
    with open(signature) as f:
        data = json.load(f)
    signed_cert = b64_to_cert(data["signed_cert"])
    ca_cert = b64_to_cert(data["ca_cert"])

    cert = Certified(config)
    cert.add_identity(signed_cert, ca_cert, overwrite)
    if "services" in data:
        xname = encode.rfc4514name(ca_cert.subject)
        add_services(cert,
                     data["services"],
                     cert_to_b64(ca_cert),
                     [xname],
                     overwrite)
    return 0

def add_services(cert: Certified,
                 services: Dict[str,str],
                 ca_cert: Optional[str] = None,
                 auths: List[str] = [],
                 overwrite: bool = False,
                ) -> None:
    for name, url in services.items():
        srv = TrustedService(
              url = url,
              cert = ca_cert,
              auths = auths
            )
        cert.add_service(name, srv, overwrite)

@app.command()
def set_org(signature : Annotated[
                        Path,
                        typer.Argument(help='json signature response containing both "signed_cert" and "ca_cert".')
                    ],
               overwrite: Annotated[bool, typer.Option(
                        help="Overwrite existing authorization?")
                    ] = False,
               config : Config = None) -> int:
    """ Setup this instance as a member of the signing organization.
    Warning:

    Removes certified/CA.crt certified/CA.key
    Removes certified/known_*/self.crt
    Removes certified/id
    Removes certified/CA

    Replaces certified/id.crt (with given cert).
    Adds/Replaces certified/known_*/org.crt (if present)
    """
    assert overwrite, "This function requires --overwrite"
    with open(signature) as f:
        data = json.load(f)

    signed_cert = b64_to_cert(data["signed_cert"])
    ca_cert = b64_to_cert(data["ca_cert"])
    cfg = layout.config(config)

    # check that id.key matches this pubkey first!
    pubkey = load_pem_private_key((cfg/"id.key").read_bytes(), None).public_key()
    if signed_cert.public_key() != pubkey:
        print("Error: new public key does not fit exising id.key.")
        exit(1)

    (cfg/"known_clients"/"org.crt").write_text(cert_to_pem(ca_cert))
    (cfg/"known_servers"/"org.crt").write_text(cert_to_pem(ca_cert))
    (cfg/"id.crt").write_text(cert_to_pem(signed_cert))
    if (cfg/"id").is_dir():
        shutil.rmtree(cfg/"id")

    for n in ["CA.key", "CA.crt"]:
        try:
            os.remove(cfg/n)
        except FileNotFoundError:
            pass
    if (cfg/"CA").is_dir():
        shutil.rmtree(cfg/"CA")
    for n in ["known_servers", "known_clients"]:
        try:
            os.remove(cfg/n/"self.crt")
        except FileNotFoundError:
            pass

    if "services" in data:
        cert = Certified(cfg)
        add_services(cert, data["services"], overwrite=overwrite)
    
    return 0

@app.command()
def get_ident(config : Config = None) -> int:
    """ Create a json copy of my certificate
    suitable for sending to a signing authority.
    """
    cert = Certified(config)
    id_cert = cert.identity().certificate
    print(cert_to_b64(id_cert))
    #sn_cert = cert.signer().certificate
    #s = json.dumps({"cert": cert_to_b64(id_cert),
    #                "ca_cert": cert_to_b64(sn_cert)
    #               })
    #print(s)
    return 0

@app.command()
def get_signer(config : Config = None) -> int:
    """ Create a json copy of my signing certificate.
    """
    cert = Certified(config)
    id_cert = cert.signer().certificate
    s = json.dumps({"ca_cert": cert_to_b64(id_cert)})
    print(s)
    return 0

"""
@app.command()
def grant(entity : str = typer.Argument(..., help="Grantee's name."),
          pubkey : str = typer.Argument(..., help="Grantee's pubkey to sign"),
          scopes : str = typer.Argument("", help="Whitespace-separated list of scopes to grant."),
          hours  : float = typer.Option(10.0, help="Hours until expiration."),
          config : Optional[Path] = typer.Option(None, help="Config file path [default ~/.config/actors.json].")):
    # Sign a biscuit and print it to stdout.
    config = cfgfile(config)
    cfg = Config.model_validate_json(open(config).read())
    #print(f"Granting actor {entity} pubkey {pubkey} and {scopes}")

    lifetime = timedelta(hours=hours)

    pubkey = PubKey(pubkey) # validate the pubkey's format
    grant = Grant( grantor = cfg.name
                 , entity = entity
                 , attr = {'scopes': scopes,
                           'pubkey': str(pubkey)
                          }
                 , expiration = datetime.now().astimezone()  + lifetime
                 )
    sgrant = signGrant(grant, cfg.privkey)
    s = json.dumps({"grants": {cfg.name: to_jsonable_python(sgrant)}}, indent=4)
    print(s)
"""

@app.command()
def serve(app : Annotated[
                  str,
                  typer.Argument(rich_help_panel="Server's ASGI application",
                       help="Example: path.to.module:attr")
                ],
          url : Annotated[
                  str,
                  typer.Argument(rich_help_panel="URL to serve application",
                       help="Example: https://127.0.0.1:8000")
                ] = "https://0.0.0.0:4433",
          loki : Annotated[
                  Optional[str],
                  typer.Option(help="json file containing url,user,passwd for sending logs to loki")
                ] = None,
          v : bool = typer.Option(False, "-v", help="show info-level logs"),
          vv : bool = typer.Option(False, "-vv", help="show debug-level logs"),
          config : Config = None) -> int:
    """
    Run the web server with HTTPS certificate-based trust setup.
    """
    if vv:
        logging.basicConfig(level=logging.DEBUG)
    elif v:
        logging.basicConfig(level=logging.INFO)

    cert = Certified(config)
    _logger.info("Running %s %s", __name__, app)
    #asyncio.run( cert.serve(app, url, loki) )
    cert.serve(app, url, loki)
    _logger.info("Exited %s", app)
    return 0

# TODO: list out identities (and key types) of all known clients or servers
# TODO: print logs of all successful and unsuccessful authentications
