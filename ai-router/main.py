"""AI Router — Multi-agent pipeline with semantic compression and Redis memory.

Usage:
    python main.py          interactive pipeline (planner → analyst → coder → validator)
    python main.py serve    task system API + background workers (requires Redis)
"""

from __future__ import annotations

import logging
import os
import sys

from core.agents import AGENTS
from core.llm import LLM
from core.memory import StateManager
from core.router import route
from storage.redis_client import RedisMemory

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

SUMMARIZE_EVERY = 3  # turns between conversation summaries


def _require_api_key() -> str:
    api_key = os.environ.get("OPENROUTER_API_KEY", "")
    if not api_key:
        logger.error(
            "OPENROUTER_API_KEY environment variable is not set. "
            "Please set it before running the router."
        )
        sys.exit(1)
    return api_key


def _connect_redis() -> RedisMemory | None:
    try:
        mem = RedisMemory(
            host=os.environ.get("REDIS_HOST", "localhost"),
            port=int(os.environ.get("REDIS_PORT", "6379")),
            db=int(os.environ.get("REDIS_DB", "0")),
            password=os.environ.get("REDIS_PASSWORD") or None,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Redis not available (%s)", exc)
        return None
    if not mem.ping():
        logger.warning("Redis not reachable")
        return None
    logger.info("Redis connection established")
    return mem


def interactive() -> None:
    llm = LLM.from_config(_require_api_key())
    redis_mem = _connect_redis()
    if redis_mem is None:
        logger.warning("Running without state persistence")
    state_mgr = StateManager(redis_mem) if redis_mem else None
    user_id = os.environ.get("USER_ID", "default_user")

    print("\n=== AI Router — Multi-Agent Pipeline ===")
    print("Type your request below. Press Ctrl+C to exit.\n")

    turns: list[str] = []
    while True:
        try:
            user_input = input("INPUT: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            break
        if not user_input:
            continue
        try:
            context = state_mgr.load_state(user_id).get("last_summary", "") if state_mgr else ""
            result = route(llm, user_input, context=context)
            if state_mgr:
                state_mgr.update_memory(user_id, {"last_input": user_input, "last_output": result[:500]})
                turns.append(f"User: {user_input}\nAssistant: {result[:2000]}")
                if len(turns) >= SUMMARIZE_EVERY:
                    state_mgr.summarize_and_store(llm, user_id, "\n\n".join(turns))
                    turns.clear()
            print("\n--- OUTPUT ---")
            print(result)
            print()
        except Exception as exc:  # noqa: BLE001
            logger.error("Pipeline error: %s", exc)
            print(f"\nError: {exc}\n")


def serve() -> None:
    import uvicorn

    from tasks.api import create_app
    from tasks.engine import TaskEngine, Worker
    from tasks.service import TaskService
    from tasks.store import TaskStore

    llm = LLM.from_config(_require_api_key())
    redis_mem = _connect_redis()
    if redis_mem is None:
        logger.error("The task system needs Redis (set REDIS_HOST/REDIS_PORT)")
        sys.exit(1)

    service = TaskService(TaskStore(redis_mem.client), AGENTS.keys())
    engine = TaskEngine(service, lambda agent, prompt: AGENTS[agent].run(llm, prompt))
    worker = Worker(engine, concurrency=int(os.environ.get("TASK_WORKERS", "2")))
    app = create_app(service, worker=worker)
    uvicorn.run(app, host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "8080")))


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "serve":
        serve()
    else:
        interactive()


if __name__ == "__main__":
    main()
