# Command-line interface to certified

import os, sys
import importlib
import asyncio
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Set
from typing_extensions import Annotated

import logging
_logger = logging.getLogger(__name__)

import typer

import certified.layout as layout
import certified.encode as encode
from .ca import CA

#from pydantic_core import to_jsonable_python
#from aiowire import EventLoop, Wire
#from actor_api.config import Config, TrustedClient, TrustedService, PubKey
#from actor_api.grant import Grant
#from actor_api.validation import signGrant, validateGrant
#from actor_api.crypto import gen_key, gen_keypair, get_verifykey, get_pubkey
#from actor_api.message import cfgfile, arun
#from actor_api.actor_test import cli_srv, srv_sign
#from actor_api.type_alias import str_to_set

app = typer.Typer()

def write_config(ca : CA, config : Path) -> None:
    ca.cert_pem.write(config / "CA.crt")
    ca.private_key_pem.write(config / "CA.key")

@app.command()
def init(email: Annotated[
                    List[str],
                    typer.Option(help="email addresses",
                        rich_help_panel="Example: example@example.org"
                    )
                ] = [],
         host: Annotated[
                    List[str],
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
""")
               ] = [],
         uri: Annotated[
                    List[str],
                    typer.Option(help="uniform resource identifiers",
                        rich_help_panel="Example: https://datatracker.ietf.org/doc/html/rfc3986#section-1.1.2"
                    )
               ] = [],
         overwrite: bool = typer.Option(False, help="Overwrite existing config."),
         config : Optional[Path] = typer.Option(None, help="Config file path [default $VIRTUAL_ENV/etc/certified].")):
    """
    Create a new config file for the user.
    """

    cfg = layout.config(config, should_exist=overwrite)
    if not overwrite and (cfg/"CA.key").exists():
        raise FileExistsError(cfg/"CA.key")
    cfg.mkdir(exist_ok=True, parents=True)

    name = encode.name("My Org.", "My Company")
    san = encode.SAN(email, host, uri)
    ca = CA.new(name, san)
    write_config(ca, cfg)
    print(f"Generated new config at {cfg}.")
    return 0

@app.command()
def new(name : str = typer.Argument(..., help="Server's network identity."),
        url : str = typer.Argument(..., help="Server's listening URL."),
        my_scopes : str = typer.Argument("", help="Whitespace-separated list of scopes that the creator will be configured with by default."),
        config : Optional[Path] = typer.Option(None, help="Config file path [default ~/.config/actors.json].")):
    """
    Create a new actor and add it to the self-config file
    with self as a trusted client.

    The server's config is output to stdout.
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

@app.command()
def grant(entity : str = typer.Argument(..., help="Grantee's name."),
          pubkey : str = typer.Argument(..., help="Grantee's pubkey to sign"),
          scopes : str = typer.Argument("", help="Whitespace-separated list of scopes to grant."),
          hours  : float = typer.Option(10.0, help="Hours until expiration."),
          config : Optional[Path] = typer.Option(None, help="Config file path [default ~/.config/actors.json].")):
    """
    Create a signed grant and print to stdout.

    The result is suitable to add to a "Config.grants" dict.
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

    The result is suitable to add to a "Config.services" dict.
    """
    config = cfgfile(config)
    cfg = Config.model_validate_json(open(config).read())
    svc = TrustedService(
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
    svc = TrustedService(
            url = cfg.listen or '',
            pubkey = get_verifykey(cfg.privkey),
            auths = set(cfg.validators.keys()),
            )
    s = json.dumps({"validators": {cfg.name: to_jsonable_python(svc)}}, indent=4)
    print(s)

@app.command()
def run(actor : str = typer.Argument(..., help="actor's python module (specified as 'module:attr')"),
        max_queries : Optional[int] = typer.Option(None, help="Number of queries to answer before closing (None for infinite)."),
        v : bool = typer.Option(False, "-v", help="show info-level logs"),
        vv : bool = typer.Option(False, "-vv", help="show debug-level logs"),
        config : Optional[Path] = typer.Option(None, help="Config file path [default ~/.config/actors.json].")):
    """
    Run the given actor's receive/respond event loop.

    That attribute should be an instance of
    :class:`actor_api.State`.

    Its configuration will set to the config provided to this program.
    """
    # args to pass in when calling wire's creation function
    args : List[str] = []
    if vv:
        logging.basicConfig(level=logging.DEBUG)
    elif v:
        logging.basicConfig(level=logging.INFO)

    config = cfgfile(config)
    cfg = Config.model_validate_json(open(config).read())

    mod_name, state_name = actor.split(':')

    sys.path.insert(0, os.getcwd())
    mod = importlib.import_module(mod_name)
    state = getattr(mod, state_name)
    if not isinstance(state, Wire):
        state = state(*args)
    if not isinstance(state, Wire):
        raise TypeError("Module does not define a runnable actor.")

    if "docs" not in state.calls:
        _logger.info("Note: you can add a docs() call to your API by writing\n"
                "    @app.call()\n"
                "    def docs() -> str:\n"
                "        return app.docs()"
                )

    state.config = cfg # type: ignore[attr-defined]
    if max_queries is not None:
        state.remaining_queries = max_queries # type: ignore[attr-defined]

    _logger.info("Running %s:%s", mod_name, state_name)
    asyncio.run( state )
    _logger.info("Exited %s:%s", mod_name, state_name)

if __name__ == "__main__":
    app()
