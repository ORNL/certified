"""
A2A agent client with certified mTLS.

Connects to an A2A agent server using certified's mTLS SSL context wired
into httpx.AsyncClient — the transport the A2A SDK expects.

References:
  A2A protocol spec:   https://a2a-protocol.org/latest/
  A2A Python SDK:      https://github.com/a2aproject/a2a-python
  certified:           https://certified.readthedocs.io/

Dependencies (not in pyproject.toml — install separately for experimentation):
  uv pip install "a2a-sdk[fastapi]" httpx

Setup:
  certified init
  # Register the server (run once after the server owner sends their intro):
  certified add-service echo-agent https://127.0.0.1:8443

Run:
  python examples/a2a/client.py "Hello from the client"
"""

from __future__ import annotations

import asyncio
import sys
import logging

import httpx

from a2a.client import ClientConfig, ClientFactory
from a2a.helpers import get_stream_response_text
from a2a.types.a2a_pb2 import Message, Part, SendMessageRequest

from certified import Certified

_logger = logging.getLogger(__name__)

SERVER_ALIAS = "echo-agent"   # must match a file in known_servers/


async def send_message(prompt: str) -> None:
    cert = Certified()

    # Look up the server's URL and cert from known_servers/echo-agent.yaml.
    srv = cert.lookup_server(SERVER_ALIAS)
    if srv is None:
        raise RuntimeError(
            f"Server '{SERVER_ALIAS}' not found in known_servers/. "
            "Run: certified add-service echo-agent https://127.0.0.1:8443"
        )

    # Build an mTLS SSL context and hand it to httpx.AsyncClient.
    # This is the bridge between certified and the A2A SDK: the SDK accepts
    # any httpx.AsyncClient, so we inject our TLS identity here.
    ssl_ctx = cert.ssl_context(is_client=True, srv=srv)
    httpx_client = httpx.AsyncClient(verify=ssl_ctx)

    factory = ClientFactory(ClientConfig(httpx_client=httpx_client))

    # create_from_url fetches /.well-known/agent-card.json over the mTLS
    # connection to discover the agent's capabilities and transport.
    client = await factory.create_from_url(srv.url)

    request = SendMessageRequest(
        message=Message(
            role="ROLE_USER",
            parts=[Part(text=prompt)],
        )
    )

    async with client:
        async for event in client.send_message(request):
            text = get_stream_response_text(event)
            if text:
                print(text)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    prompt = " ".join(sys.argv[1:]) or "Hello, agent!"
    asyncio.run(send_message(prompt))
