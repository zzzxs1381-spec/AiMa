import threading

import fakeredis

from core.agents import AGENTS
from core.batcher import BatchQueue
from core.llm import LLM, LLMError
from storage.redis_client import RedisMemory


class FakeLLM:
    def __init__(self, fail=False, during=None):
        self.prompts = []
        self.fail = fail
        self.during = during

    def fallback_call(self, prompt, temperature=None):
        self.prompts.append(prompt)
        if self.during:
            self.during()
        if self.fail:
            raise LLMError("down")
        return "ok"


def test_agents_loaded_from_config():
    assert AGENTS["validator"].temperature == 0.1
    assert "Security concerns" in AGENTS["validator"].prompt
    assert AGENTS["analyst"].model == "openai/gpt-4o-mini"


def test_batch_flush_keeps_requests_added_during_flush():
    q = BatchQueue()
    q.add_request("a")
    q.add_request("b")
    llm = FakeLLM(during=lambda: q.add_request("late"))
    assert q.flush(llm) == "ok"
    assert llm.prompts == ["a\n\n---\n\nb"]
    assert q.size == 1


def test_batch_flush_failure_requeues():
    q = BatchQueue()
    q.add_request("a")
    try:
        q.flush(FakeLLM(fail=True))
    except LLMError:
        pass
    assert q.size == 1


def test_llm_call_falls_back(monkeypatch):
    llm = LLM("k", fallback_chain=["m1", "m2"])
    seen = []

    def fake(model, prompt, temperature=None):
        seen.append((model, temperature))
        if model in ("primary", "m1"):
            raise LLMError("x")
        return "from " + model

    monkeypatch.setattr(llm, "_request", fake)
    assert llm.call("primary", "p", temperature=0.5) == "from m2"
    assert seen[0] == ("primary", 0.5)


def test_redis_memory_corrupted_state_and_ping():
    client = fakeredis.FakeRedis(decode_responses=True)
    mem = RedisMemory(client=client)
    assert mem.ping()
    client.set("state:u", "{not json")
    assert mem.load_state("u") == {}
    mem.update_memory("u", {"a": 1})
    assert mem.load_state("u") == {"a": 1}
    _ = threading  # keep import used
