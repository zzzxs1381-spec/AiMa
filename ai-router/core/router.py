from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from core.agents import AGENTS
from core.compressor import semantic_compress

if TYPE_CHECKING:
    from core.llm import LLM

logger = logging.getLogger(__name__)


def route(llm: LLM, user_input: str, context: str = "") -> str:
    """Run the full multi-agent pipeline on user input.

    Pipeline:
        1. Semantic compression of input (long inputs only)
        2. Planner agent breaks task into steps
        3. Analyst agent extracts insights from the plan
        4. Coder agent produces code/output from request + plan + analysis
        5. Validator agent checks the result against the original request

    Every stage now sees the original request; previously each agent only saw
    the previous agent's output, so the coder never saw what the user asked.
    """
    logger.info("Starting pipeline for input: %.100s...", user_input)

    request = semantic_compress(llm, user_input)
    if context:
        request = f"Conversation context:\n{context}\n\nRequest:\n{request}"

    plan = AGENTS["planner"].run(llm, request)
    analysis = AGENTS["analyst"].run(llm, f"Request:\n{request}\n\nPlan:\n{plan}")
    code = AGENTS["coder"].run(
        llm, f"Request:\n{request}\n\nPlan:\n{plan}\n\nAnalysis:\n{analysis}"
    )
    review = AGENTS["validator"].run(llm, f"Request:\n{request}\n\nSolution:\n{code}")
    logger.info("Pipeline complete.")

    return f"{code}\n\n--- REVIEW ---\n{review}"
