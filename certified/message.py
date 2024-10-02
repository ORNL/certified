# Command-line interface to interact with certified APIs

import os
import json
from enum import Enum
from typing import Optional, Dict, List
from typing_extensions import Annotated
from urllib.parse import urlsplit, urlunsplit

import logging
_logger = logging.getLogger(__name__)

import typer

from httpx import Request

from certified import Certified
from .certified import Config

class HTTPMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"

app = typer.Typer()

@app.command()
def message(url: Annotated[
                    str,
                    typer.Argument(help="Service's Resource URL"),
                ],
         data : Annotated[
                    Optional[str],
                    typer.Argument(
                        rich_help_panel="json-formatted message body",
                        help="""If present, the message is POST-ed to the URL.
Example: '{"refs": [1,2], "query": "What's the weather?"}'
""")
                ] = None,
         H: Annotated[
                    List[str],
                    typer.Option("-H",
                        rich_help_panel="headers to pass",
                        help="""Interpreted as curl interprets them (split once on ": ").
Example: -H "X-Token: ABC" gets parsed as headers = {"X-Token": "ABC"}.
""")
                ] = [],
         X: Annotated[
                    Optional[HTTPMethod],
                    typer.Option("-X", help="HTTP method to use."),
                ] = None,
         v : bool = typer.Option(False, "-v", help="show info-level logs"),
         vv : bool = typer.Option(False, "-vv", help="show debug-level logs"),
         config : Config = None):
    """
    Send a json-message to an mTLS-authenticated HTTPS-REST-API.
    """
    if vv:
        logging.basicConfig(level=logging.DEBUG)
    elif v:
        logging.basicConfig(level=logging.INFO)

    # Validate arguments
    if X is None:
        X = HTTPMethod.POST if data else HTTPMethod.GET

    cert = Certified(config)
    headers : Dict[str,str] = {}
    if data:
        headers["Content-Type"] = "application/json"
    for hdr in H:
        u = hdr.split(": ", 1)
        if len(u) != 2:
            raise ValueError(f"Invalid header: '{hdr}'")
        headers[u[0]] = u[1]

    # Rewrite the URL so that the scheme and netloc appear in the base.
    (scheme, netloc, path, query, fragment) = urlsplit(url)
    base = urlunsplit((scheme, netloc,"","",""))
    url  = urlunsplit(("","",path,query,fragment))

    with cert.Client(base, headers=headers) as cli:
        if data:
            assert X == HTTPMethod.POST
            ddata = json.loads(data)
            resp = cli.post(url, json=ddata)
        else:
            assert X == HTTPMethod.GET
            resp = cli.get(url)
    if resp.status_code != 200:
        return resp.status_code

    print(resp.text)
    return 0
