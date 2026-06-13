# Integrate with A2A

The [Agent2Agent (A2A) protocol](https://a2a-protocol.org/latest/) is an open standard
for conversations between AI agents. Where a REST call says "fetch this resource," an A2A
exchange says "here is a message; work on it and emit artifacts as you go." Agents discover
each other's capabilities through a signed **Agent Card**, communicate over JSON-RPC, and
stream results back as structured events.

`certified` fits into A2A at the transport layer: it wraps every connection in mutual TLS
so each side knows the verified identity of the other before a single A2A message is
exchanged.

---

## Why mTLS matters for A2A

In a standard A2A deployment, authentication is described in the Agent Card's
`security_schemes` field. Without mTLS the common choices are API keys or OAuth bearer
tokens, which authenticate the *request* but leave the *connection* unverified. A
compromised intermediary can relay requests with a stolen token.

mTLS authenticates the *connection*. The client's x509 certificate is verified against the
server's `known_clients/` trust store during the TLS handshake — before any HTTP bytes
flow. The server knows it is talking to a specific entity with a specific key, not just
someone who holds a token string.

### Agent Card: mTLS only

```json
{
  "name": "compute-agent",
  "version": "1.0.0",
  "supported_interfaces": [
    { "protocol_binding": "jsonrpc", "url": "https://compute.ornl.gov:8443" }
  ],
  "security_schemes": {
    "mtls": {
      "type": "mutualTLS",
      "description": "Client must present a certificate signed by the ORNL CA."
    }
  },
  "security_requirements": [{ "mtls": [] }]
}
```

### Agent Card: mTLS transport + biscuit authorisation

Layering a biscuit token on top adds *authorisation* without giving up the identity
guarantee that mTLS provides. The `certified` two-layer model maps cleanly:

| Layer | Mechanism | Answers |
|---|---|---|
| Transport | x509 mTLS | *Who are you?* |
| Request | Biscuit in `Bearer:` header | *What may you do?* |

```json
{
  "name": "compute-agent",
  "version": "1.0.0",
  "supported_interfaces": [
    { "protocol_binding": "jsonrpc", "url": "https://compute.ornl.gov:8443" }
  ],
  "security_schemes": {
    "mtls": {
      "type": "mutualTLS",
      "description": "Client must present a certificate signed by the ORNL CA."
    },
    "biscuit": {
      "type": "http",
      "scheme": "bearer",
      "bearerFormat": "biscuit",
      "description": "Biscuit token issued by the ORNL CA, passed in the Bearer header."
    }
  },
  "security_requirements": [{ "mtls": [], "biscuit": [] }]
}
```

Clients that pass mTLS but lack a valid biscuit are authenticated (the server knows who
they are) but not authorised to act. See [Authorization Model](../concepts/authz.md) for
how to issue and validate biscuit tokens.

---

## Server example

Full source: `examples/a2a/server.py` in the repository.

```bash
# install deps (not in pyproject.toml)
uv pip install "a2a-sdk[fastapi]"

python examples/a2a/server.py
```

### Wrapping an A2A app with mTLS

`cert.serve()` accepts any ASGI app, including A2A's FastAPI application:

```python
from certified import Certified
from fastapi import FastAPI

cert = Certified()
app = build_app()          # returns an A2A FastAPI app
cert.serve(app, BASE_URL)  # uvicorn + mTLS, blocks until interrupted
```

Incoming connections must present a certificate trusted by the server's `known_clients/`
directory. Connections that fail the handshake are dropped by the TLS layer before the
ASGI app is reached.

### Reading the peer identity

`certified`'s uvicorn monkey-patch threads the TLS `transport` object into every
request's ASGI scope. A2A servers receive requests via Starlette's `Request` object, so
peer identity is one call away:

```python
def _extract_peer_cn(request: Request) -> str | None:
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
```

Wire this into A2A's `ServerCallContextBuilder` to populate `ServerCallContext.user`:

```python
class CertifiedContextBuilder(ServerCallContextBuilder):
    def build(self, request: Request) -> ServerCallContext:
        cn = _extract_peer_cn(request)
        user = PeerCertUser(cn) if cn else UnauthenticatedUser()
        return ServerCallContext(user=user, state={"headers": dict(request.headers)})
```

Inside any `AgentExecutor`, the caller's identity is then available as:

```python
async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
    caller = context.call_context.user.user_name  # the peer cert CN
```

---

## Client example

Full source: `examples/a2a/client.py` in the repository.

```bash
# install deps (not in pyproject.toml)
uv pip install "a2a-sdk[fastapi]" httpx

# register the server once
certified add-service echo-agent https://127.0.0.1:8443

python examples/a2a/client.py "Hello, agent!"
```

### Wiring mTLS into the A2A SDK

A2A's `ClientFactory` accepts a pre-built `httpx.AsyncClient`. There are two patterns
depending on who controls the client lifecycle.

**Pattern 1 — you control the lifecycle** (`cert.AsyncClient`)

Use this for simple async calls where you open a session, make requests, and close it
yourself:

```python
async with cert.AsyncClient("https://echo-agent") as http:
    r = await http.get("/echo/ping")
    r.raise_for_status()
```

**Pattern 2 — the framework controls the lifecycle** (`cert.ssl_context`)

Use this when you need to hand a pre-configured `httpx.AsyncClient` to a library. A2A's
`ClientFactory` owns the client's lifetime, so pass the raw client:

```python
srv = cert.lookup_server("echo-agent")
ssl_ctx = cert.ssl_context(is_client=True, srv=srv)   # mTLS context for this peer
httpx_client = httpx.AsyncClient(verify=ssl_ctx)       # httpx client, unmanaged

factory = ClientFactory(ClientConfig(httpx_client=httpx_client))
client = await factory.create_from_url(srv.url)        # fetches agent card, negotiates transport
```

`create_from_url` fetches `/.well-known/agent-card.json` over the already-authenticated
mTLS connection and negotiates the transport protocol from the card. Everything after that
is standard A2A:

```python
request = SendMessageRequest(
    message=Message(role="ROLE_USER", parts=[Part(text=prompt)])
)
async with client:
    async for event in client.send_message(request):
        text = get_stream_response_text(event)
        if text:
            print(text)
```

---

## Summary

| Concern | How `certified` handles it |
|---|---|
| Server mTLS | `cert.serve(a2a_app, url)` — one line |
| Peer identity on server | `request.scope['transport'].get_extra_info('peercert')` |
| Client mTLS (simple) | `cert.AsyncClient("https://peer")` |
| Client mTLS (framework) | `httpx.AsyncClient(verify=cert.ssl_context(True, srv))` |
| Alias resolution | `cert.lookup_server(name)` reads `known_servers/<name>.yaml` |
| Authorisation layer | Biscuit token in `Bearer:` header — see [Authorization Model](../concepts/authz.md) |
