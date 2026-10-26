"""Executes queued tasks with agents: single, multi (individually) and pair (worker ↔ reviewer)."""

from __future__ import annotations

import concurrent.futures as cf
import logging
import threading
from collections.abc import Callable

from tasks.models import (
    ACTIVE,
    TERMINAL,
    AssignmentMode,
    AssignmentStatus,
    PairRound,
    Task,
    TaskStatus,
)
from tasks.service import TaskService

logger = logging.getLogger(__name__)

AgentRunner = Callable[[str, str], str]  # (agent_name, prompt) -> output

REVIEW_INSTRUCTIONS = (
    "You are reviewing the work of another agent for the task below.\n"
    "Reply with APPROVED on the first line if the work fully solves the task.\n"
    "Otherwise reply with CHANGES_REQUESTED on the first line followed by concrete fixes."
)


class Cancelled(Exception):
    pass


class AttemptTimeout(Exception):
    pass


def is_approved(review: str) -> bool:
    first = review.strip().splitlines()[0].upper() if review.strip() else ""
    return "APPROVED" in first and "CHANGES_REQUESTED" not in first and "NOT APPROVED" not in first


class TaskEngine:
    def __init__(self, service: TaskService, runner: AgentRunner, max_parallel_agents: int = 4) -> None:
        self.service = service
        self.store = service.store
        self.runner = runner
        self.pool = cf.ThreadPoolExecutor(max_workers=max_parallel_agents, thread_name_prefix="agent")

    @property
    def clock(self) -> Callable[[], float]:
        return self.service.clock

    # ─── housekeeping ───────────────────────────────────────────────────
    def housekeeping(self) -> None:
        ts = self.clock()
        for tid in self.store.pop_due_retries(ts):
            with self.store.lock(tid):
                task = self.store.get_task(tid)
                if task and task.status == TaskStatus.RETRY_WAIT:
                    task.status = TaskStatus.PENDING
                    task.next_attempt_at = None
                    self.service._evaluate_readiness(task)
                    self.store.save_task(task)
        for task in self.store.all_tasks():
            if task.deadline is not None and task.deadline <= ts and task.status not in TERMINAL | ACTIVE:
                self._time_out(task.id, "deadline passed before the task could run")

    def _time_out(self, task_id: str, reason: str) -> None:
        with self.store.lock(task_id):
            task = self.store.get_task(task_id)
            if not task or task.status in TERMINAL:
                return
            self.store.remove_from_queues(task_id)
            task.status = TaskStatus.TIMED_OUT
            task.error = reason
            task.finished_at = self.clock()
            task.unread = True
            self.service._event(task, "timed_out", reason)
            self.store.save_task(task)
        self.service.propagate(task_id)

    # ─── main step ──────────────────────────────────────────────────────
    def run_once(self) -> str | None:
        """Housekeeping + run the highest-priority queued task. Returns the task id or None."""
        self.housekeeping()
        task_id = self.store.dequeue()
        if task_id is None:
            return None
        self.process(task_id)
        return task_id

    def run_until_idle(self, max_steps: int = 1000) -> int:
        steps = 0
        while steps < max_steps and self.run_once():
            steps += 1
        return steps

    def process(self, task_id: str) -> None:
        with self.store.lock(task_id):
            task = self.store.get_task(task_id)
            if not task or task.status != TaskStatus.QUEUED:
                return
            expired = task.deadline is not None and task.deadline <= self.clock()
            if not expired:
                task.status = TaskStatus.RUNNING
                task.attempts += 1
                task.started_at = task.started_at or self.clock()
                task.error = None
                self.service._event(task, "started", f"attempt {task.attempts}/{task.max_retries + 1}")
                self.store.save_task(task)
        if expired:
            self._time_out(task_id, "deadline passed before the task could run")
            return

        try:
            if task.mode == AssignmentMode.PAIR:
                self._run_pair(task)
            else:
                self._run_individual(task)
        except Cancelled:
            logger.info("task %s cancelled while running", task_id)
            return
        except Exception as exc:  # noqa: BLE001 - any agent failure counts as a failed attempt
            self._attempt_failed(task_id, exc)
            return
        self._finish(task_id)

    # ─── execution helpers ──────────────────────────────────────────────
    def _context(self, task: Task) -> str:
        parts = [f"Task: {task.title}"]
        if task.description:
            parts.append(task.description)
        for dep_id in task.depends_on:
            dep = self.store.get_task(dep_id)
            if dep and dep.result:
                parts.append(f"Result of dependency '{dep.title}':\n{dep.result}")
        if task.comments:
            parts.append("Notes:\n" + "\n".join(f"- {c.author}: {c.text}" for c in task.comments))
        return "\n\n".join(parts)

    def _remaining(self, task: Task) -> float:
        limit = task.timeout_seconds
        if task.deadline is not None:
            limit = min(limit, task.deadline - self.clock())
        if limit <= 0:
            raise AttemptTimeout("deadline reached")
        return limit

    def _call(self, task: Task, agent: str, prompt: str) -> str:
        self._ensure_not_cancelled(task.id)
        future = self.pool.submit(self.runner, agent, prompt)
        try:
            out = future.result(timeout=self._remaining(task))
        except cf.TimeoutError as exc:
            future.cancel()
            raise AttemptTimeout(f"agent {agent} exceeded {task.timeout_seconds:.0f}s") from exc
        if not isinstance(out, str) or not out.strip():
            raise RuntimeError(f"agent {agent} returned empty output")
        return out

    def _ensure_not_cancelled(self, task_id: str) -> None:
        cur = self.store.get_task(task_id)
        if cur is None or cur.status == TaskStatus.CANCELLED:
            raise Cancelled()

    def _save(self, task_id: str, mutate: Callable[[Task], None]) -> Task:
        """Apply a mutation to the latest stored copy unless it was cancelled meanwhile."""
        with self.store.lock(task_id):
            cur = self.store.get_task(task_id)
            if cur is None or cur.status == TaskStatus.CANCELLED:
                raise Cancelled()
            mutate(cur)
            self.store.save_task(cur)
            return cur

    def _run_individual(self, task: Task) -> None:
        prompt = self._context(task)
        todo = [a.agent for a in task.assignments if a.status != AssignmentStatus.DONE]

        def mark_running(t: Task) -> None:
            for a in t.assignments:
                if a.agent in todo:
                    a.status, a.started_at, a.error = AssignmentStatus.RUNNING, self.clock(), None

        self._save(task.id, mark_running)
        lock = threading.Lock()
        errors: list[str] = []
        timeouts: list[str] = []

        def work(agent: str) -> None:
            try:
                out = self._call(task, agent, prompt)
                ok, err = True, None
            except Cancelled:
                raise
            except Exception as exc:  # noqa: BLE001
                out, ok, err = None, False, f"{type(exc).__name__}: {exc}"
                if isinstance(exc, AttemptTimeout):
                    with lock:
                        timeouts.append(agent)
            with lock:
                if err:
                    errors.append(f"{agent}: {err}")

            def apply(t: Task) -> None:
                for a in t.assignments:
                    if a.agent == agent:
                        a.status = AssignmentStatus.DONE if ok else AssignmentStatus.FAILED
                        a.result, a.error, a.finished_at = out, err, self.clock()
                self.service._event(
                    t, "agent_done" if ok else "agent_failed", err or f"{agent} finished", agent, agent=agent
                )

            self._save(task.id, apply)

        threads = [threading.Thread(target=self._guard(work), args=(a,)) for a in todo]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        self._ensure_not_cancelled(task.id)
        if errors:
            if len(timeouts) == len(errors):
                raise AttemptTimeout("; ".join(errors))
            raise RuntimeError("; ".join(errors))

    @staticmethod
    def _guard(fn: Callable[[str], None]) -> Callable[[str], None]:
        def inner(agent: str) -> None:
            try:
                fn(agent)
            except Cancelled:
                pass

        return inner

    def _run_pair(self, task: Task) -> None:
        pair = self.service.get_pair(task.pair_id or "")
        base = self._context(task)
        feedback = ""
        work = ""
        for rnd in range(1, pair.max_rounds + 1):
            prompt = base if not feedback else (
                f"{base}\n\nYour previous attempt:\n{work}\n\nReviewer feedback to address:\n{feedback}"
            )
            work = self._call(task, pair.worker, prompt)

            def to_review(t: Task, rnd: int = rnd) -> None:
                t.status = TaskStatus.REVIEW
                self.service._event(t, "review", f"round {rnd}: {pair.reviewer} reviews", pair.reviewer,
                                    agent=pair.reviewer)

            self._save(task.id, to_review)
            review = self._call(task, pair.reviewer, f"{REVIEW_INSTRUCTIONS}\n\n{base}\n\nWork:\n{work}")
            approved = is_approved(review)

            def record(t: Task, rnd: int = rnd, work: str = work, review: str = review, ok: bool = approved) -> None:
                t.pair_rounds.append(PairRound(round=rnd, work=work, review=review, approved=ok))
                t.status = TaskStatus.RUNNING
                t.approved = ok
                self.service._event(
                    t, "pair_round", f"round {rnd}: {'approved' if ok else 'changes requested'}",
                    pair.reviewer, agent=pair.reviewer, round=rnd,
                )
                for a in t.assignments:
                    a.status = AssignmentStatus.DONE if ok or rnd == pair.max_rounds else AssignmentStatus.RUNNING
                    a.result = work if a.agent == pair.worker else review

            self._save(task.id, record)
            if approved:
                return
            feedback = review

    def _finish(self, task_id: str) -> None:
        def done(t: Task) -> None:
            t.status = TaskStatus.DONE
            t.finished_at = self.clock()
            t.unread = True
            if t.mode == AssignmentMode.PAIR:
                last = t.pair_rounds[-1] if t.pair_rounds else None
                t.result = last.work if last else None
                note = "approved" if t.approved else "max rounds reached without approval"
                self.service._event(t, "done", f"pair finished: {note}")
            elif t.mode == AssignmentMode.SINGLE:
                t.result = t.assignments[0].result
                self.service._event(t, "done", "completed")
            else:
                t.result = "\n\n".join(f"### {a.agent}\n{a.result}" for a in t.assignments)
                self.service._event(t, "done", f"all {len(t.assignments)} agents completed")

        try:
            self._save(task_id, done)
        except Cancelled:
            return
        self.service.propagate(task_id)

    def _attempt_failed(self, task_id: str, exc: Exception) -> None:
        reason = f"{type(exc).__name__}: {exc}"
        final = False

        def fail(t: Task) -> None:
            nonlocal final
            t.error = reason
            deadline_passed = t.deadline is not None and t.deadline <= self.clock()
            if t.attempts <= t.max_retries and not deadline_passed:
                delay = t.retry_backoff_seconds * (2 ** (t.attempts - 1))
                t.status = TaskStatus.RETRY_WAIT
                t.next_attempt_at = self.clock() + delay
                self.store.schedule_retry(t.id, t.next_attempt_at)
                self.service._event(t, "attempt_failed", f"{reason}; retry in {delay:.0f}s")
            else:
                final = True
                timed_out = deadline_passed or isinstance(exc, AttemptTimeout)
                t.status = TaskStatus.TIMED_OUT if timed_out else TaskStatus.FAILED
                t.finished_at = self.clock()
                t.unread = True
                self.service._event(t, t.status.value, reason)

        try:
            self._save(task_id, fail)
        except Cancelled:
            return
        if final:
            self.service.propagate(task_id)

    def shutdown(self) -> None:
        self.pool.shutdown(wait=False, cancel_futures=True)


class Worker:
    """Background threads that keep pulling tasks from the Redis priority queue."""

    def __init__(self, engine: TaskEngine, concurrency: int = 2, poll_interval: float = 0.5) -> None:
        self.engine = engine
        self.concurrency = concurrency
        self.poll_interval = poll_interval
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        for i in range(self.concurrency):
            th = threading.Thread(target=self._loop, name=f"task-worker-{i}", daemon=True)
            th.start()
            self._threads.append(th)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                if self.engine.run_once() is None:
                    self._stop.wait(self.poll_interval)
            except Exception:  # noqa: BLE001
                logger.exception("task worker iteration failed")
                self._stop.wait(self.poll_interval)

    def stop(self) -> None:
        self._stop.set()
        for th in self._threads:
            th.join(timeout=5)
        self.engine.shutdown()
