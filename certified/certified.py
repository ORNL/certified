# Command-line interface to certified

import os, sys, shutil
import importlib
import asyncio
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Set
from typing_extensions import Annotated

import logging
_logger = logging.getLogger(__name__)

import typer

from certified import Certified
import certified.encode as encode
from .ca import CA

#from actor_api.grant import Grant
#from actor_api.validation import signGrant, validateGrant
#from actor_api.crypto import gen_key, gen_keypair, get_verifykey, get_pubkey
#from actor_api.actor_test import cli_srv, srv_sign
#from actor_api.type_alias import str_to_set

app = typer.Typer()


Email = Annotated[ List[str],
                   typer.Option(help="email addresses",
                        rich_help_panel="Example: example@example.org"
                 ) ]
Hostname = Annotated[ List[str],
                      typer.Option(help="host names",
                        rich_help_panel="""Examples:
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
                 typer.Option(help="uniform resource identifiers",
                        rich_help_panel="Example: https://datatracker.ietf.org/doc/html/rfc3986#section-1.1.2"
               ) ]
Config = Annotated[Optional[Path], typer.Option(
                        help="Config file path [default $VIRTUAL_ENV/etc/certified].") ]

@app.command()
def init(name: Annotated[
                    Optional[str],
                    typer.Argument(help="Person Name",
                        rich_help_panel="""Note, name parsing into given and surnames
and generations, etc. is not supported.

Examples:
    - Timothy T. Tester
""")
                ] = None,
         org: Annotated[
                    Optional[str],
                    typer.Option(help="Organization Name",
                        rich_help_panel="""If specified, unit must also be present and name cannot be present.
Example: 'Certificate Lab, Inc.'"
""")
                ] = None,
         unit: Annotated[
                    Optional[str],
                    typer.Option(help="Organization Unit",
                        rich_help_panel="""If specified, org must also be present and name cannot be present.
Example: 'Computing Directorate'
""")
                ] = None,
         email: Email = [],
         host: Hostname = [],
         uri: URI = [],
         overwrite: Annotated[bool, typer.Option(
                        help="Overwrite existing config.")
                    ] = False,
         config : Config = None):
    """
    Create a new signing and end-entity ID.
    """

    # Validate arguments
    if org or unit:
        assert unit, "If org is defined, unit must also be defined."
        assert unit, "If unit is defined, org must also be defined."
        assert name is None, "If org is defined, name must not be defined."
        name1 = encode.org_name(org, unit, pseudonym=f"Signing Key for O={org},OU={unit}")
        name2 = encode.org_name(org, unit)
    elif name:
        assert org is None, "If name is defined, org must not be defined."
        assert unit is None, "If name is defined, unit must not be defined."
        name1  = encode.person_name(name, pseudonym=f"Signing key for CN={name}")
        name2 = encode.person_name(name)
    else:
        raise AssertionError("No identities provided.")
    if sum(map(len, [email, host, uri])) > 0:
        san  = encode.SAN(email, host, uri)
    else:
        raise ValueError("Host, Email, or URI must also be provided.")

    cert = Certified.new(name1, name2, san, config, overwrite)
    print(f"Generated new config at {cert.config}.")
    return 0

@app.command()
def new(host : Hostname = [],
        url : str = typer.Argument(..., help="Server's listening URL."),
        my_scopes : str = typer.Argument("", help="Whitespace-separated list of scopes that the creator will be configured with by default."),
        config : Optional[Path] = typer.Option(None, help="Config file path [default ~/.config/actors.json].")):
    """
    Create a new identity and add it as a trusted server:

      - it will appear in {config}/known_servers
      - your `CA.crt` will appear in {server}/known_clients/origin.crt
      - your listed scopes will appear next to that file as `origin.scope`
    """

    scopes = str_to_set(my_scopes)

    config = cfgfile(config)
    cfg = Config.model_validate_json(open(config).read())

    app = Config( name = name
                , privkey = gen_key()
                , listen = url
                )
    # add cfg as a client of app (2-sided add)
    cli_srv(cfg, app, scopes)

    # print the new app's config to stdout
    write_config(None, app)

    # save the user's modified config.
    write_config(config, cfg)

def introduce():
    # TODO
    pass

@app.command()
def grant(entity : str = typer.Argument(..., help="Grantee's name."),
          pubkey : str = typer.Argument(..., help="Grantee's pubkey to sign"),
          scopes : str = typer.Argument("", help="Whitespace-separated list of scopes to grant."),
          hours  : float = typer.Option(10.0, help="Hours until expiration."),
          config : Optional[Path] = typer.Option(None, help="Config file path [default ~/.config/actors.json].")):
    """
    Sign a token and print it to stdout.
    """
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

@app.command()
def pubkey(
          config : Optional[Path] = typer.Option(None, help="Config file path [default ~/.config/actors.json].")):
    """
    Print out the public key that corresponds to this config.
    """
    config = cfgfile(config)
    cfg = Config.model_validate_json(open(config).read())
    svc = KnownService(
            url = cfg.listen or '',
            pubkey = get_pubkey(cfg.privkey),
            auths = set(cfg.validators.keys()),
            )
    s = json.dumps({"services": {cfg.name: to_jsonable_python(svc)}}, indent=4)
    print(s)

@app.command()
def verifykey(
          config : Optional[Path] = typer.Option(None, help="Config file path [default ~/.config/actors.json].")):
    """
    Print out the validation key that corresponds to signatures
    generated from this config.

    The result is suitable to add to a "Config.validators" dict.
    """
    config = cfgfile(config)
    cfg = Config.model_validate_json(open(config).read())
    svc = KnownService(
            url = cfg.listen or '',
            pubkey = get_verifykey(cfg.privkey),
            auths = set(cfg.validators.keys()),
            )
    s = json.dumps({"validators": {cfg.name: to_jsonable_python(svc)}}, indent=4)
    print(s)

@app.command()
def serve(app : Annotated[
                  str,
                  typer.Argument(help="Server's ASGI application",
                       rich_help_panel="Example: path.to.module:attr")
                ],
          url : Annotated[
                  str,
                  typer.Argument(help="URL to serve application",
                       rich_help_panel="Example: https://127.0.0.1:8000")
                ] = "https://0.0.0.0:4433",
          v : bool = typer.Option(False, "-v", help="show info-level logs"),
          vv : bool = typer.Option(False, "-vv", help="show debug-level logs"),
          config : Config = None):
    """
    Run the web server with HTTPS certificate-based trust setup.
    """
    if vv:
        logging.basicConfig(level=logging.DEBUG)
    elif v:
        logging.basicConfig(level=logging.INFO)

    cert = Certified(config)
    _logger.info("Running %s", app)
    cert.serve(app, url)
    _logger.info("Exited %s", app)

# TODO: list out identities (and key types) of all known clients or servers
# TODO: print logs of all successful and unsuccessful authentications
if __name__ == "__main__":
    app()
