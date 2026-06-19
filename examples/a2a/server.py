"""
A2A agent server with certified mTLS.

Runs a minimal A2A-compliant echo agent behind certified's mTLS layer.
Incoming connections must present a certificate trusted by this server's
known_clients/ directory — identity is extracted from the peer cert and
made available to the agent as ServerCallContext.user.

References:
  A2A protocol spec:   https://a2a-protocol.org/latest/
  A2A Python SDK:      https://github.com/a2aproject/a2a-python
  certified:           https://certified.readthedocs.io/

Dependencies (not in pyproject.toml — install separately for experimentation):
  uv pip install "a2a-sdk[fastapi]"

Setup:
  certified init                          # create your identity
  certified add-client <peer-name> ...    # or use introduce/add-intro for cross-org

Run:
  python examples/a2a/server.py
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request

from a2a.auth.user import User, UnauthenticatedUser
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.context import ServerCallContext
from a2a.server.events import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import (
    ServerCallContextBuilder,
    add_a2a_routes_to_fastapi,
    create_agent_card_routes,
    create_jsonrpc_routes,
)
from a2a.server.tasks import InMemoryTaskStore, TaskUpdater
from a2a.types.a2a_pb2 import (
    AgentCard,
    AgentCapabilities,
    AgentInterface,
    AgentSkill,
    Part,
    TaskState,
)
from a2a.utils.constants import TransportProtocol

from certified import Certified

_logger = logging.getLogger(__name__)

HOST = "127.0.0.1"
PORT = 8443
BASE_URL = f"https://{HOST}:{PORT}"


# ── peer-cert identity ────────────────────────────────────────────────────────
# certified's uvicorn monkey-patch threads `transport` into each request scope,
# so we can read the TLS peer certificate from request.scope['transport'].

class PeerCertUser(User):
    """A2A User backed by an x509 peer certificate common name."""

    def __init__(self, cn: str):
        self._cn = cn

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def user_name(self) -> str:
        return self._cn


def _extract_peer_cn(request: Request) -> str | None:
    """Read the peer certificate CN from the TLS transport, if present."""
    transport = request.scope.get("transport")
    if transport is None:
        return None
    peercert = transport.get_extra_info("peercert")
    if not peercert:
        return None
    for field, value in peercert.get("subject", ()):
        if field == "commonName":
            return value
    return None


class CertifiedContextBuilder(ServerCallContextBuilder):
    """Builds ServerCallContext with identity from the mTLS peer certificate."""

    def build(self, request: Request) -> ServerCallContext:
        state = {"headers": dict(request.headers)}
        cn = _extract_peer_cn(request)
        user: User = PeerCertUser(cn) if cn else UnauthenticatedUser()
        return ServerCallContext(user=user, state=state)


# ── agent executor ────────────────────────────────────────────────────────────

class EchoAgentExecutor(AgentExecutor):
    """Minimal executor: echoes the user's message back with their identity."""

    async def execute(
        self, context: RequestContext, event_queue: EventQueue
    ) -> None:
        caller = context.call_context.user.user_name or "unknown"
        text = context.get_user_input()
        _logger.info("Request from %s: %r", caller, text)

        updater = TaskUpdater(
            event_queue,
            task_id=context.task_id or "",
            context_id=context.context_id or "",
        )
        await updater.update_status(TaskState.TASK_STATE_WORKING)
        await updater.add_artifact(
            parts=[Part(text=f"[{caller}] {text}")],
            artifact_id="echo",
        )
        await updater.complete()

    async def cancel(
        self, context: RequestContext, event_queue: EventQueue
    ) -> None:
        updater = TaskUpdater(
            event_queue,
            task_id=context.task_id or "",
            context_id=context.context_id or "",
        )
        await updater.update_status(TaskState.TASK_STATE_CANCELED)


# ── agent card ────────────────────────────────────────────────────────────────

AGENT_CARD = AgentCard(
    name="echo-agent",
    description=(
        "mTLS-authenticated echo agent. "
        "Replies with the caller's cert CN and their message."
    ),
    version="0.1.0",
    capabilities=AgentCapabilities(streaming=True),
    default_input_modes=["text/plain"],
    default_output_modes=["text/plain"],
    skills=[
        AgentSkill(
            id="echo",
            name="Echo",
            description="Echoes input text, prefixed with the caller's identity.",
            input_modes=["text/plain"],
            output_modes=["text/plain"],
        )
    ],
    supported_interfaces=[
        AgentInterface(
            protocol_binding=TransportProtocol.JSONRPC,
            url=BASE_URL,
        )
    ],
)


# ── FastAPI app ───────────────────────────────────────────────────────────────

def build_app() -> FastAPI:
    task_store = InMemoryTaskStore()
    executor = EchoAgentExecutor()
    handler = DefaultRequestHandler(
        agent_executor=executor,
        task_store=task_store,
        agent_card=AGENT_CARD,
    )
    context_builder = CertifiedContextBuilder()

    app = FastAPI(title="echo-agent")
    add_a2a_routes_to_fastapi(
        app,
        agent_card_routes=create_agent_card_routes(AGENT_CARD),
        jsonrpc_routes=create_jsonrpc_routes(
            handler, rpc_url="/", context_builder=context_builder
        ),
    )
    return app


# ── entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    cert = Certified()
    app = build_app()
    # cert.serve() wraps any ASGI app with mTLS using uvicorn.
    # Clients must present a certificate trusted by known_clients/.
    cert.serve(app, BASE_URL)
