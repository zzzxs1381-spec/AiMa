from __future__ import annotations

from typing import TYPE_CHECKING

from core.config import models_config, prompts_config

if TYPE_CHECKING:
    from core.llm import LLM

DEFAULT_COMPRESS_PROMPT = """\
You are a semantic compressor. Compress the following text WITHOUT losing meaning.
Keep only:
- key facts
- decisions
- entities and relationships
- action items

Remove repetition, filler words, and redundant phrasing.
Output compact JSON or bullet points.
"""

# Inputs shorter than this are passed through: compressing them costs a call and loses detail.
MIN_COMPRESS_CHARS = 400


def semantic_compress(llm: LLM, text: str, *, force: bool = False) -> str:
    """Compress text semantically using the compressor model from config."""
    if not force and len(text) < MIN_COMPRESS_CHARS:
        return text
    cfg = models_config().get("compressor", {}) or {}
    prompt = prompts_config().get("compressor", DEFAULT_COMPRESS_PROMPT)
    return llm.call(
        cfg.get("model", "openai/gpt-4o-mini"),
        prompt + "\n\n" + text,
        temperature=cfg.get("temperature"),
    )
