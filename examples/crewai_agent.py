"""
CrewAI agent with certified mTLS.

The custom tool uses cert.Client() (sync httpx) so it drops cleanly into
CrewAI's synchronous _run() interface without any event-loop gymnastics.

Dependencies:
    uv add crewai

Setup (run once on each machine):
    certified init
    certified add-intro ...   # exchange intros with the data service owner

Run the data service in one terminal:
    python examples/crewai_agent.py --serve

Run the crew in another:
    python examples/crewai_agent.py --crew "Summarize the status of all jobs."
"""

import argparse
from typing import Type

from pydantic import BaseModel
from certified import Certified

cert = Certified()


# ── mTLS-aware tool ───────────────────────────────────────────────────────────

from crewai.tools import BaseTool  # type: ignore[import-not-found]


class JobStatusInput(BaseModel):
    job_id: str


class JobStatusTool(BaseTool):
    name: str = "get_job_status"
    description: str = "Fetch the current status of a submitted HPC job."
    args_schema: Type[BaseModel] = JobStatusInput

    def _run(self, job_id: str) -> str:
        with cert.Client(base_url="https://scheduler-svc") as client:
            resp = client.get(f"/jobs/{job_id}")
            resp.raise_for_status()
        return resp.text


class ListJobsTool(BaseTool):
    name: str = "list_jobs"
    description: str = "List all jobs in the queue."
    args_schema: Type[BaseModel] = BaseModel

    def _run(self) -> str:
        with cert.Client(base_url="https://scheduler-svc") as client:
            resp = client.get("/jobs")
            resp.raise_for_status()
        return resp.text


# ── crew ──────────────────────────────────────────────────────────────────────

from crewai import Agent, Task, Crew  # type: ignore[import-not-found]

tools = [ListJobsTool(), JobStatusTool()]

analyst = Agent(
    role="HPC Job Analyst",
    goal="Monitor and report on cluster job status.",
    backstory="You query the scheduler API and summarize job health.",
    tools=tools,
    verbose=True,
)


def build_crew(prompt: str) -> Crew:
    task = Task(
        description=prompt,
        expected_output="A plain-English summary of job status.",
        agent=analyst,
    )
    return Crew(agents=[analyst], tasks=[task], verbose=True)


# ── server (for testing) ──────────────────────────────────────────────────────

import json
from fastapi import FastAPI
from typing import Dict, Any

app = FastAPI()

JOBS: Dict[str, Any] = {
    "job-001": {"status": "running",  "progress": "72%"},
    "job-002": {"status": "queued",   "progress": "0%"},
    "job-003": {"status": "complete", "progress": "100%"},
}


@app.get("/jobs")
async def list_jobs():
    return JOBS


@app.get("/jobs/{job_id}")
async def get_job(job_id: str):
    if job_id not in JOBS:
        from fastapi import HTTPException
        raise HTTPException(404, "job not found")
    return JOBS[job_id]


# ── main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--crew", metavar="PROMPT")
    args = parser.parse_args()

    if args.serve:
        # Register this service before running the crew:
        #   certified add-service scheduler-svc https://127.0.0.1:8443
        cert.serve(app, "https://127.0.0.1:8443")

    elif args.crew:
        crew = build_crew(args.crew)
        result = crew.kickoff()
        print(result)
    else:
        parser.print_help()
