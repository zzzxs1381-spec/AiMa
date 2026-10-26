import sys
from pathlib import Path

import fakeredis
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tasks.engine import TaskEngine  # noqa: E402
from tasks.service import TaskService  # noqa: E402
from tasks.store import TaskStore  # noqa: E402

AGENT_NAMES = ["planner", "coder", "analyst", "summarizer", "validator"]


class Clock:
    def __init__(self, t: float = 1_800_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, s: float) -> None:
        self.t += s


class ScriptedRunner:
    """Deterministic agent runner for tests: records calls, replies by agent."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.replies: dict[str, list] = {}

    def __call__(self, agent: str, prompt: str) -> str:
        self.calls.append((agent, prompt))
        queue = self.replies.get(agent)
        if queue:
            r = queue.pop(0)
            if isinstance(r, Exception):
                raise r
            return r
        return f"{agent} output"


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def redis_client():
    return fakeredis.FakeRedis(decode_responses=True)


@pytest.fixture
def service(redis_client, clock):
    return TaskService(TaskStore(redis_client), AGENT_NAMES, clock=clock)


@pytest.fixture
def runner():
    return ScriptedRunner()


@pytest.fixture
def engine(service, runner):
    eng = TaskEngine(service, runner)
    yield eng
    eng.shutdown()
