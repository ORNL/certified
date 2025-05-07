# Command-line interface to interact with certified APIs

import asyncio
import os
import json
from enum import Enum
from typing import Optional, Dict, List, Union
from typing_extensions import Annotated
from urllib.parse import urlsplit, urlunsplit
from pathlib import Path
import sys

import logging
_logger = logging.getLogger(__name__)

import typer
import aiohttp
import yaml # type: ignore[import-untyped]

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
         json_file: Annotated[
                    Optional[Path],
                    typer.Option("--json",
                        rich_help_panel="json-formatted message body",
                        help="If present, contents are POST-ed to the URL.")
                ] = None,
         yaml_file: Annotated[
                    Optional[Path],
                    typer.Option("--yaml",
                        rich_help_panel="yaml-formatted message body",
                        help="If present, contents are converted to json and POST-ed to the URL.")
                ] = None,
         pp: Annotated[
                    bool,
                    typer.Option(
                        rich_help_panel="pretty-print json output?",
                        help="Re-format json output with spaces and indentation.")
                ] = False,
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

    has_data = False
    ddata = None
    if data is not None:
        has_data = True
        ddata = json.loads(data)
    if json_file is not None:
        assert not has_data, "Only one of <data> or --json or --yaml allowed."
        has_data = True
        with open(json_file, "r", encoding="utf-8") as f:
            ddata = json.load(f)
    if yaml_file is not None:
        assert not has_data, "Only one of <data> or --json or --yaml allowed."
        has_data = True
        with open(yaml_file, "r", encoding="utf-8") as f:
            ddata = yaml.safe_load(f)

    # Validate arguments
    if X is None:
        X = HTTPMethod.POST if has_data else HTTPMethod.GET

    cert = Certified(config)
    headers : Dict[str,str] = {}

    if has_data:
        headers["Content-Type"] = "application/json"
        #assert X in [HTTPMethod.POST,
        #             HTTPMethod.PUT,
        #             HTTPMethod.PATCH]
    for hdr in H:
        u = hdr.split(": ", 1)
        if len(u) != 2:
            raise ValueError(f"Invalid header: '{hdr}'")
        headers[u[0]] = u[1]

    # Rewrite the URL so that the scheme and netloc appear in the base.
    (scheme, netloc, path, query, fragment) = urlsplit(url)
    base = urlunsplit((scheme, netloc,"","",""))
    url  = urlunsplit(("","",path,query,fragment))

    async def do_call() -> Union[int,str]:
        async with cert.ClientSession(base, headers=headers) as cli:
            async with cli.request(X.value, url, json=ddata) as resp:
                if pp:
                    msg = json.dumps(await resp.json(), indent=2)
                else:
                    msg = await resp.text()
                if resp.status//100 != 2:
                    print("Error: %s", msg, file=sys.stderr)
                    return resp.status
                return msg

    ret: Union[int,str] = 1
    try:
        ret = asyncio.run(do_call())
    except aiohttp.ClientConnectorError as err:
        print(f"Connection error occurred: {err}", file=sys.stderr)
    except asyncio.TimeoutError:
        print("Request timed out", file=sys.stderr)
    except aiohttp.InvalidURL:
        print("Invalid URL provided", file=sys.stderr)
    except aiohttp.ContentTypeError as err:
        print(f"Unexpected content type in response: {err}",file=sys.stderr)

    if isinstance(ret, int):
        sys.exit( ret )
    print(ret)
    sys.exit(0)
