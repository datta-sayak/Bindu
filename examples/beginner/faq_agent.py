"""
Bindu Docs QA Agent 🌻
Answers questions about Bindu documentation.
"""

import os
from dotenv import load_dotenv

load_dotenv()

from bindu.penguin.bindufy import bindufy

from agno.agent import Agent
from agno.models.openrouter import OpenRouter
from agno.tools.duckduckgo import DuckDuckGoTools


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------
agent = Agent(
    name="Bindu Docs Agent",
    instructions="""
You are an expert assistant for Bindu.
When answering questions, first search the Bindu documentation at docs.getbindu.com for the most accurate and up-to-date information.
Use web search to find relevant documentation pages, then provide comprehensive answers based on what you find.
Always cite your sources by mentioning the specific documentation pages you used.
If you cannot find information in the docs, say so clearly.
""",
    model=OpenRouter(
        id="openai/gpt-oss-120b",
        api_key=os.getenv("OPENROUTER_API_KEY"),
    ),
    tools=[DuckDuckGoTools()],
)

# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------
def handler(messages):
    return agent.run(messages[-1]["content"])

# ---------------------------------------------------------------------------
# Bindu config
# ---------------------------------------------------------------------------
config = {
    "author": "your.email@example.com",
    "name": "bindu_docs_agent",
    "description": "Answers questions about Bindu documentation",
    "deployment": {"url": "http://localhost:3773", "expose": True},
    "skills": [],
}

bindufy(config, handler)
