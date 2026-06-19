"""
Google ADK agent with certified mTLS.

Google ADK function tools are plain Python callables. cert.Client() (sync
httpx) fits naturally; the mTLS handshake is invisible to ADK itself.

Dependencies:
    uv add google-adk

Setup (run once on each machine):
    certified init
    certified add-intro ...   # exchange intros with the data service owner

Run the data service in one terminal:
    python examples/google_adk_agent.py --serve

Run the agent in another:
    python examples/google_adk_agent.py --agent "What datasets are available?"
"""

import argparse
from certified import Certified

cert = Certified()


# ── mTLS-aware tools ──────────────────────────────────────────────────────────

def list_datasets() -> dict:
    """List datasets available on the data service."""
    with cert.Client(base_url="https://data-svc") as client:
        resp = client.get("/datasets")
        resp.raise_for_status()
    return resp.json()


def get_dataset(name: str) -> dict:
    """Fetch metadata for a specific dataset by name."""
    with cert.Client(base_url="https://data-svc") as client:
        resp = client.get(f"/datasets/{name}")
        resp.raise_for_status()
    return resp.json()


# ── agent ─────────────────────────────────────────────────────────────────────

from google.adk.agents import Agent  # type: ignore[import-not-found]
from google.adk.runners import Runner  # type: ignore[import-not-found]
from google.adk.sessions import InMemorySessionService  # type: ignore[import-not-found]
from google.genai.types import Content, Part  # type: ignore[import-not-found]

data_agent = Agent(
    name="data_agent",
    model="gemini-2.0-flash",
    description="Answers questions about datasets on the data service.",
    instruction="Use the tools to look up available datasets and their metadata.",
    tools=[list_datasets, get_dataset],
)


async def run_agent(prompt: str) -> str:
    import asyncio
    sessions = InMemorySessionService()
    runner = Runner(
        agent=data_agent,
        app_name="certified-example",
        session_service=sessions,
    )
    session = await sessions.create_session(
        app_name="certified-example", user_id="user"
    )
    content = Content(role="user", parts=[Part(text=prompt)])
    final = ""
    async for event in runner.run_async(
        user_id="user",
        session_id=session.id,
        new_message=content,
    ):
        if event.is_final_response() and event.content and event.content.parts:
            final = event.content.parts[0].text
    return final


# ── server (for testing) ──────────────────────────────────────────────────────

from fastapi import FastAPI, HTTPException
from typing import Dict, Any

app = FastAPI()

DATASETS: Dict[str, Any] = {
    "climate-2024": {"rows": 4_200_000, "format": "netCDF4", "owner": "alice@ornl.gov"},
    "neutron-flux":  {"rows":   850_000, "format": "HDF5",    "owner": "bob@nist.gov"},
}


@app.get("/datasets")
async def list_ds():
    return list(DATASETS.keys())


@app.get("/datasets/{name}")
async def get_ds(name: str):
    if name not in DATASETS:
        raise HTTPException(404, "dataset not found")
    return DATASETS[name]


# ── main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--agent", metavar="PROMPT")
    args = parser.parse_args()

    if args.serve:
        # Register this service before running the agent:
        #   certified add-service data-svc https://127.0.0.1:8443
        cert.serve(app, "https://127.0.0.1:8443")

    elif args.agent:
        import asyncio
        result = asyncio.run(run_agent(args.agent))
        print(result)
    else:
        parser.print_help()
