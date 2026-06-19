"""
LangGraph agent with certified mTLS.

The agent is given a tool that calls a protected microservice over mTLS.
The Certified wrapper handles certificate selection and SSL context — the
tool itself just makes a normal async HTTP call.

Dependencies:
    uv add langgraph langchain-anthropic

Setup (run once on each machine):
    certified init          # create your identity
    certified add-intro ... # exchange intros with the service owner

Run the server in one terminal:
    python examples/langgraph_agent.py --serve

Run the agent in another:
    python examples/langgraph_agent.py --agent "What is 2+2?"
"""

import argparse
import asyncio
from typing import Annotated

from certified import Certified

cert = Certified()


# ── mTLS-aware tool ───────────────────────────────────────────────────────────

from langchain_core.tools import tool  # type: ignore[import-not-found]


@tool
async def call_compute(expression: Annotated[str, "Python expression to evaluate"]) -> str:
    """Evaluate an expression on the remote compute service."""
    async with cert.ClientSession(base_url="https://compute-svc") as client:
        async with client.post("/eval", json={"expr": expression}) as resp:
            resp.raise_for_status()
            data = await resp.json()
    return str(data["result"])


# ── graph ─────────────────────────────────────────────────────────────────────

from langchain_anthropic import ChatAnthropic  # type: ignore[import-not-found]
from langgraph.graph import StateGraph, MessagesState, START  # type: ignore[import-not-found]
from langgraph.prebuilt import ToolNode, tools_condition  # type: ignore[import-not-found]

tools = [call_compute]
llm = ChatAnthropic(model="claude-haiku-4-5-20251001").bind_tools(tools)


async def agent_node(state: MessagesState):
    return {"messages": [await llm.ainvoke(state["messages"])]}


def build_graph():
    graph = StateGraph(MessagesState)
    graph.add_node("agent", agent_node)
    graph.add_node("tools", ToolNode(tools))
    graph.add_edge(START, "agent")
    graph.add_conditional_edges("agent", tools_condition)
    graph.add_edge("tools", "agent")
    return graph.compile()


# ── server (for testing) ──────────────────────────────────────────────────────

from fastapi import FastAPI, Body
from typing import Any

app = FastAPI()


@app.post("/eval")
async def evaluate(payload: Any = Body(None)):
    try:
        result = eval(str(payload["expr"]), {"__builtins__": {}})  # noqa: S307
    except Exception as exc:
        return {"error": str(exc)}
    return {"result": result}


# ── main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--agent", metavar="PROMPT")
    args = parser.parse_args()

    if args.serve:
        # Register this service as "compute-svc" in your known_servers dir
        # before running the agent:
        #   certified add-service compute-svc https://127.0.0.1:8443
        cert.serve(app, "https://127.0.0.1:8443")

    elif args.agent:
        from langchain_core.messages import HumanMessage

        graph = build_graph()

        async def run():
            result = await graph.ainvoke({"messages": [HumanMessage(args.agent)]})
            print(result["messages"][-1].content)

        asyncio.run(run())
    else:
        parser.print_help()
