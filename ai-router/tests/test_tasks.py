import time

import pytest

from tasks.models import (
    CommentCreate,
    PairCreate,
    Priority,
    TaskCreate,
    TaskStatus,
    TaskUpdate,
)
from tasks.service import Conflict, TaskError


def mk(service, **kw):
    kw.setdefault("title", "t")
    if not any(k in kw for k in ("agent", "agents", "pair_id")):
        kw["agent"] = "coder"
    return service.create(TaskCreate(**kw))


def test_single_assignment_runs_and_notifies(service, engine, runner):
    t = mk(service, title="Write parser", description="CSV", agent="coder")
    assert t.status == TaskStatus.QUEUED
    engine.run_until_idle()
    t = service.get(t.id)
    assert t.status == TaskStatus.DONE
    assert t.result == "coder output"
    assert t.unread is True
    assert runner.calls[0][0] == "coder" and "Write parser" in runner.calls[0][1]
    assert [e.type for e in t.history][:3] == ["created", "queued", "started"]
    assert service.mark_read(t.id).unread is False


def test_multi_assignment_each_agent_individually(service, engine, runner):
    t = mk(service, agents=["analyst", "planner", "analyst"])
    assert [a.agent for a in t.assignments] == ["analyst", "planner"]
    engine.run_until_idle()
    t = service.get(t.id)
    assert t.status == TaskStatus.DONE
    assert {a.agent: a.result for a in t.assignments} == {
        "analyst": "analyst output",
        "planner": "planner output",
    }
    assert "### analyst" in t.result and "### planner" in t.result


def test_unknown_agent_and_target_validation(service):
    with pytest.raises(TaskError):
        mk(service, agent="nobody")
    with pytest.raises(ValueError):
        TaskCreate(title="x", agent="coder", agents=["planner"])


def test_priority_queue_order(service, engine, runner, clock):
    low = mk(service, title="low", priority=Priority.LOW)
    clock.advance(1)
    crit = mk(service, title="crit", priority=Priority.CRITICAL)
    clock.advance(1)
    high = mk(service, title="high", priority=Priority.HIGH)
    clock.advance(1)
    high2 = mk(service, title="high2", priority=Priority.HIGH)
    order = [engine.run_once() for _ in range(4)]
    assert order == [crit.id, high.id, high2.id, low.id]


def test_priority_change_reorders_queue(service, engine):
    a = mk(service, title="a", priority=Priority.LOW)
    b = mk(service, title="b", priority=Priority.MEDIUM)
    service.update(a.id, TaskUpdate(priority=Priority.CRITICAL))
    assert engine.run_once() == a.id
    assert engine.run_once() == b.id


def test_pair_iterates_until_approved(service, engine, runner):
    pair = service.create_pair(PairCreate(name="code+review", worker="coder", reviewer="validator", max_rounds=3))
    runner.replies["coder"] = ["v1", "v2"]
    runner.replies["validator"] = ["CHANGES_REQUESTED\nhandle empty input", "APPROVED\nlooks good"]
    t = mk(service, pair_id=pair.id, title="fn")
    engine.run_until_idle()
    t = service.get(t.id)
    assert t.status == TaskStatus.DONE
    assert t.approved is True
    assert t.result == "v2"
    assert len(t.pair_rounds) == 2
    second_coder_prompt = [p for a, p in runner.calls if a == "coder"][1]
    assert "handle empty input" in second_coder_prompt and "v1" in second_coder_prompt


def test_pair_max_rounds_without_approval(service, engine, runner):
    pair = service.create_pair(PairCreate(name="p", worker="coder", reviewer="validator", max_rounds=2))
    runner.replies["validator"] = ["CHANGES_REQUESTED a", "CHANGES_REQUESTED b"]
    t = mk(service, pair_id=pair.id)
    engine.run_until_idle()
    t = service.get(t.id)
    assert t.status == TaskStatus.DONE and t.approved is False and len(t.pair_rounds) == 2


def test_pair_management(service):
    with pytest.raises(TaskError):
        service.create_pair(PairCreate(name="bad", worker="coder", reviewer="coder"))
    pair = service.create_pair(PairCreate(name="p", worker="coder", reviewer="validator"))
    t = mk(service, pair_id=pair.id)
    service.update_pair(pair.id, __import__("tasks.models", fromlist=["PairUpdate"]).PairUpdate(reviewer="analyst"))
    assert [a.agent for a in service.get(t.id).assignments] == ["coder", "analyst"]
    with pytest.raises(Conflict):
        service.delete_pair(pair.id)  # unfinished task uses it
    service.cancel(t.id)
    service.delete_pair(pair.id)
    assert service.store.get_pair(pair.id) is None


def test_dependencies_block_then_unblock_and_pass_results(service, engine, runner):
    a = mk(service, title="plan", agent="planner")
    b = mk(service, title="build", agent="coder", depends_on=[a.id])
    assert b.status == TaskStatus.PENDING
    assert engine.run_once() == a.id
    assert service.get(b.id).status == TaskStatus.QUEUED
    engine.run_until_idle()
    assert service.get(b.id).status == TaskStatus.DONE
    coder_prompt = [p for ag, p in runner.calls if ag == "coder"][0]
    assert "planner output" in coder_prompt


def test_dependency_failure_cascades(service, engine, runner):
    runner.replies["planner"] = [RuntimeError("boom")]
    a = mk(service, agent="planner", max_retries=0)
    b = mk(service, depends_on=[a.id])
    c = mk(service, depends_on=[b.id])
    engine.run_until_idle()
    assert service.get(a.id).status == TaskStatus.FAILED
    assert service.get(b.id).status == TaskStatus.FAILED
    assert service.get(c.id).status == TaskStatus.FAILED
    assert "dependency failed" in service.get(c.id).error


def test_dependency_cycle_rejected(service):
    a = mk(service)
    b = mk(service, depends_on=[a.id])
    with pytest.raises(TaskError):
        service.update(a.id, TaskUpdate(depends_on=[b.id]))
    with pytest.raises(TaskError):
        service.update(a.id, TaskUpdate(depends_on=[a.id]))


def test_retry_with_backoff_then_success(service, engine, runner, clock):
    runner.replies["coder"] = [RuntimeError("rate limited")]
    t = mk(service, max_retries=2, retry_backoff_seconds=10)
    engine.run_once()
    t = service.get(t.id)
    assert t.status == TaskStatus.RETRY_WAIT and t.attempts == 1
    assert engine.run_once() is None  # backoff not elapsed
    clock.advance(11)
    engine.run_until_idle()
    t = service.get(t.id)
    assert t.status == TaskStatus.DONE and t.attempts == 2


def test_retries_exhausted_fail(service, engine, runner, clock):
    runner.replies["coder"] = [RuntimeError("e1"), RuntimeError("e2")]
    t = mk(service, max_retries=1, retry_backoff_seconds=0)
    engine.run_once()
    clock.advance(1)
    engine.run_until_idle()
    t = service.get(t.id)
    assert t.status == TaskStatus.FAILED and t.attempts == 2 and "e2" in t.error
    service.retry(t.id)
    engine.run_until_idle()
    assert service.get(t.id).status == TaskStatus.DONE


def test_multi_retry_only_reruns_failed_agents(service, engine, runner, clock):
    runner.replies["analyst"] = [RuntimeError("x")]
    t = mk(service, agents=["planner", "analyst"], retry_backoff_seconds=0)
    engine.run_once()
    clock.advance(1)
    engine.run_until_idle()
    assert service.get(t.id).status == TaskStatus.DONE
    assert [a for a, _ in runner.calls].count("planner") == 1


def test_deadline_times_out_queued_task(service, engine, clock):
    t = mk(service, deadline_in_seconds=60)
    clock.advance(61)
    engine.run_until_idle()
    assert service.get(t.id).status == TaskStatus.TIMED_OUT


def test_attempt_timeout(service, engine, runner):
    def slow(agent, prompt):
        time.sleep(1.5)
        return "late"

    engine.runner = slow
    t = mk(service, timeout_seconds=0.2, max_retries=0)
    engine.run_until_idle()
    t = service.get(t.id)
    assert t.status == TaskStatus.TIMED_OUT


def test_cancel_and_edit_rules(service, engine):
    t = mk(service)
    service.update(t.id, TaskUpdate(title="new", agents=["planner", "analyst"], tags=["Backend"]))
    t = service.get(t.id)
    assert t.title == "new" and t.agents == ["planner", "analyst"] and t.tags == ["backend"]
    service.cancel(t.id, reason="not needed")
    assert service.get(t.id).status == TaskStatus.CANCELLED
    assert engine.run_once() is None  # removed from queue
    with pytest.raises(Conflict):
        service.cancel(t.id)
    with pytest.raises(Conflict):
        service.update(t.id, TaskUpdate(agent="coder"))


def test_delete_rules(service):
    a = mk(service)
    b = mk(service, depends_on=[a.id])
    with pytest.raises(Conflict):
        service.delete(a.id)
    service.delete(b.id)
    service.delete(a.id)
    assert service.store.all_tasks() == []


def test_filters_search_sort(service, engine, clock):
    a = mk(service, title="Fix login bug", priority=Priority.HIGH, tags=["auth"], agent="coder")
    clock.advance(1)
    mk(service, title="Write docs", priority=Priority.LOW, agent="summarizer", deadline_in_seconds=10)
    clock.advance(1)
    c = mk(service, title="Analyze logs", priority=Priority.CRITICAL, agents=["analyst", "coder"])
    service.add_comment(a.id, CommentCreate(text="see Sentry issue", author="malik"))
    assert [t.id for t in service.list(agent="coder")[1]] == [c.id, a.id]
    assert service.list(q="sentry")[1][0].id == a.id
    assert service.list(tag="AUTH")[0] == 1
    assert service.list(priority=[Priority.LOW])[1][0].title == "Write docs"
    assert [t.title for t in service.list(sort="title", order="asc")[1]][0] == "Analyze logs"
    clock.advance(20)
    assert service.list(overdue=True)[1][0].title == "Write docs"
    total, page = service.list(limit=1, offset=1)
    assert total == 3 and len(page) == 1
    with pytest.raises(TaskError):
        service.list(sort="bogus")


def test_activity_log_and_overview(service, engine):
    t = mk(service, agent="analyst")
    engine.run_until_idle()
    types = [e.type for e in service.store.events(task_id=t.id)]
    assert "created" in types and "done" in types
    ov = {o["agent"]: o for o in service.agent_overview()}
    assert ov["analyst"]["total"] == 1 and ov["analyst"]["unread"] == 1
    assert service.stats()["by_status"] == {"done": 1}
