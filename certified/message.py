# Command-line interface to interact with certified APIs

import os
import json
from enum import Enum
from typing import Optional
from typing_extensions import Annotated

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

    with cert.Client() as cli:
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
