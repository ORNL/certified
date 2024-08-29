# Command-line interface to interact with certified APIs

import os
import json
from enum import Enum
from typing import Optional, Dict, List
from typing_extensions import Annotated
from urllib.parse import urlsplit, urlunsplit

import logging
_logging = logging.getLogger(__name__)

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
                    typer.Argument(help="json-formatted message body",
                        rich_help_panel="""If present, the message is POST-ed to the URL.
Example: '{"refs": [1,2], "query": "What's the weather?"}'
""")
                ] = None,
         H: Annotated[
                    List[str],
                    typer.Option(help="headers to pass",
                        rich_help_panel="""Interpreted as curl interprets them (split once on ": ").
Example: -H "X-Token: ABC" gets parsed as headers = {"X-Token": "ABC"}.
""")
                ] = [],
         X: Annotated[
                    Optional[HTTPMethod],
                    typer.Option(help="HTTP method to use."),
                ] = None,
         config : Config = None):
    """
    Send a json-message to an mTLS-authenticated HTTPS-REST-API.
    """
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
    #url  = urlunsplit(("","",path,query,fragment))

    with cert.Client(base, headers=headers) as cli:
        if data:
            ddata = json.loads(data)
            req = Request(X.value, url, json=ddata)
        else:
            req = Request(X.value, url)
        resp = cli.send(req)
    if resp.status_code != 200:
        return resp.status_code

    print(resp.text)
    return 0
