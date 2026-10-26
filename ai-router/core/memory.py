from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from core.compressor import semantic_compress

if TYPE_CHECKING:
    from core.llm import LLM
    from storage.redis_client import RedisMemory

logger = logging.getLogger(__name__)


class StateManager:
    """Manages per-user conversational state with Redis-backed persistence."""

    def __init__(self, redis: RedisMemory) -> None:
        self.redis = redis

    def load_state(self, user_id: str) -> dict[str, Any]:
        return self.redis.load_state(user_id)

    def save_state(self, user_id: str, state: dict[str, Any]) -> None:
        self.redis.save_state(user_id, state)

    def update_memory(self, user_id: str, new_info: dict[str, Any]) -> None:
        state = self.load_state(user_id)
        state.update(new_info)
        self.save_state(user_id, state)

    def summarize_and_store(
        self, llm: LLM, user_id: str, conversation: str
    ) -> None:
        """Compress a conversation and store the summary in state."""
        previous = self.load_state(user_id).get("last_summary", "")
        text = f"{previous}\n\n{conversation}" if previous else conversation
        summary = semantic_compress(llm, text, force=True)
        self.update_memory(user_id, {"last_summary": summary})
        logger.info("Stored compressed summary for user %s", user_id)
