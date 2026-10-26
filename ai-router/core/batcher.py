from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.llm import LLM

logger = logging.getLogger(__name__)


class BatchQueue:
    """Collects requests and flushes them as a single batched prompt."""

    def __init__(self) -> None:
        self._queue: list[str] = []
        self._lock = threading.Lock()

    def add_request(self, request: str) -> None:
        with self._lock:
            self._queue.append(request)
            logger.debug("Queued request (total: %d)", len(self._queue))

    def flush(self, llm: LLM) -> str:
        """Merge all queued requests into one prompt and send via fallback chain."""
        with self._lock:
            if not self._queue:
                return ""

            # Take a snapshot and detach it, so requests added while the LLM call
            # is in flight are not silently dropped (previous code cleared them).
            batch = self._queue
            self._queue = []

        batch_prompt = "\n\n---\n\n".join(batch)
        logger.info("Flushing batch of %d merged requests", len(batch))
        try:
            return llm.fallback_call(batch_prompt)
        except Exception:
            with self._lock:
                self._queue = batch + self._queue  # keep them for a retry
            raise

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._queue)
