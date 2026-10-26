from __future__ import annotations

from typing import TYPE_CHECKING

from core.config import models_config, prompts_config

if TYPE_CHECKING:
    from core.llm import LLM


class Agent:
    """A single-purpose agent that processes input through an LLM with a role-specific prompt."""

    def __init__(
        self,
        name: str,
        prompt: str,
        model: str,
        temperature: float | None = None,
        description: str = "",
    ) -> None:
        self.name = name
        self.prompt = prompt
        self.model = model
        self.temperature = temperature
        self.description = description

    def run(self, llm: LLM, input_text: str) -> str:
        return llm.call(self.model, self.prompt + "\n\n" + input_text, temperature=self.temperature)

    def __repr__(self) -> str:
        return f"Agent(name={self.name!r}, model={self.model!r})"


_DEFAULTS: dict[str, tuple[str, str]] = {
    "planner": ("Break the following task into clear, actionable steps.", "openai/gpt-4o"),
    "coder": ("Write optimized, production-ready code for the following task.", "openai/gpt-4o"),
    "analyst": (
        "Analyze the following and extract key insights, patterns, and recommendations.",
        "openai/gpt-4o-mini",
    ),
    "summarizer": (
        "Compress the following text into its key points without losing meaning.",
        "openai/gpt-4o-mini",
    ),
    "validator": (
        "Check the following for correctness, errors, and potential improvements.",
        "openai/gpt-4o",
    ),
}


def build_agents() -> dict[str, Agent]:
    """Build agents from config/models.yaml + config/prompts.yaml, falling back to defaults."""
    models = models_config().get("agents", {}) or {}
    prompts = prompts_config()
    agents: dict[str, Agent] = {}
    for name in dict.fromkeys([*_DEFAULTS, *models]):
        default_prompt, default_model = _DEFAULTS.get(name, ("", "openai/gpt-4o-mini"))
        cfg = models.get(name, {}) or {}
        agents[name] = Agent(
            name,
            prompts.get(name, default_prompt),
            cfg.get("model", default_model),
            cfg.get("temperature"),
            cfg.get("description", ""),
        )
    return agents


AGENTS: dict[str, Agent] = build_agents()
