"""Redis persistence for tasks, pairs, the priority queue and the activity log."""

from __future__ import annotations

import contextlib
from collections.abc import Iterator

import redis

from tasks.models import Event, Pair, Priority, Task

EVENTS_LIMIT = 2000


class TaskStore:
    def __init__(self, client: redis.Redis, prefix: str = "airouter") -> None:
        self.r = client
        self.p = prefix

    # keys
    def _k(self, *parts: str) -> str:
        return ":".join((self.p, *parts))

    # ─── tasks ──────────────────────────────────────────────────────────
    def save_task(self, task: Task) -> None:
        pipe = self.r.pipeline()
        pipe.set(self._k("task", task.id), task.model_dump_json())
        pipe.sadd(self._k("tasks"), task.id)
        pipe.execute()

    def get_task(self, task_id: str) -> Task | None:
        raw = self.r.get(self._k("task", task_id))
        return Task.model_validate_json(raw) if raw else None

    def delete_task(self, task_id: str) -> None:
        pipe = self.r.pipeline()
        pipe.delete(self._k("task", task_id))
        pipe.srem(self._k("tasks"), task_id)
        pipe.zrem(self._k("queue"), task_id)
        pipe.zrem(self._k("delayed"), task_id)
        pipe.execute()

    def all_tasks(self) -> list[Task]:
        ids = sorted(self.r.smembers(self._k("tasks")))
        if not ids:
            return []
        raws = self.r.mget([self._k("task", i) for i in ids])
        return [Task.model_validate_json(raw) for raw in raws if raw]

    @contextlib.contextmanager
    def lock(self, task_id: str, timeout: float = 30) -> Iterator[None]:
        with self.r.lock(self._k("lock", task_id), timeout=timeout, blocking_timeout=timeout):
            yield

    # ─── priority queue ─────────────────────────────────────────────────
    @staticmethod
    def queue_score(priority: Priority, created_at: float) -> float:
        # Lower score pops first: higher priority first, then FIFO by creation time.
        return (3 - priority.rank) * 1e11 + created_at

    def enqueue(self, task: Task) -> None:
        self.r.zrem(self._k("delayed"), task.id)
        self.r.zadd(self._k("queue"), {task.id: self.queue_score(task.priority, task.created_at)})

    def dequeue(self) -> str | None:
        popped = self.r.zpopmin(self._k("queue"), 1)
        return popped[0][0] if popped else None

    def remove_from_queues(self, task_id: str) -> None:
        self.r.zrem(self._k("queue"), task_id)
        self.r.zrem(self._k("delayed"), task_id)

    def queued_ids(self) -> list[str]:
        return list(self.r.zrange(self._k("queue"), 0, -1))

    def schedule_retry(self, task_id: str, ready_at: float) -> None:
        self.r.zadd(self._k("delayed"), {task_id: ready_at})

    def pop_due_retries(self, now: float) -> list[str]:
        key = self._k("delayed")
        due = self.r.zrangebyscore(key, "-inf", now)
        removed = []
        for tid in due:
            if self.r.zrem(key, tid):  # only the worker that removes it promotes it
                removed.append(tid)
        return removed

    # ─── pairs ──────────────────────────────────────────────────────────
    def save_pair(self, pair: Pair) -> None:
        self.r.set(self._k("pair", pair.id), pair.model_dump_json())
        self.r.sadd(self._k("pairs"), pair.id)

    def get_pair(self, pair_id: str) -> Pair | None:
        raw = self.r.get(self._k("pair", pair_id))
        return Pair.model_validate_json(raw) if raw else None

    def delete_pair(self, pair_id: str) -> None:
        self.r.delete(self._k("pair", pair_id))
        self.r.srem(self._k("pairs"), pair_id)

    def all_pairs(self) -> list[Pair]:
        ids = sorted(self.r.smembers(self._k("pairs")))
        raws = self.r.mget([self._k("pair", i) for i in ids]) if ids else []
        return [Pair.model_validate_json(raw) for raw in raws if raw]

    # ─── activity log ───────────────────────────────────────────────────
    def add_event(self, event: Event) -> None:
        key = self._k("events")
        self.r.lpush(key, event.model_dump_json())
        self.r.ltrim(key, 0, EVENTS_LIMIT - 1)

    def events(self, limit: int = 100, task_id: str | None = None, agent: str | None = None) -> list[Event]:
        out: list[Event] = []
        for raw in self.r.lrange(self._k("events"), 0, EVENTS_LIMIT - 1):
            ev = Event.model_validate_json(raw)
            if task_id and ev.task_id != task_id:
                continue
            if agent and ev.data.get("agent") != agent:
                continue
            out.append(ev)
            if len(out) >= limit:
                break
        return out
