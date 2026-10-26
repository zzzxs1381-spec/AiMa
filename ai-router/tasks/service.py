"""Business logic: create/edit/cancel/retry tasks, dependencies, pairs, filtering."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from tasks.models import (
    ACTIVE,
    TERMINAL,
    Assignment,
    AssignmentMode,
    AssignmentStatus,
    Comment,
    CommentCreate,
    Event,
    Pair,
    PairCreate,
    PairUpdate,
    Priority,
    Task,
    TaskCreate,
    TaskStatus,
    TaskUpdate,
    now,
)
from tasks.store import TaskStore


class TaskError(Exception):
    """Validation / state error; `status_code` maps to HTTP."""

    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


class NotFound(TaskError):
    def __init__(self, message: str) -> None:
        super().__init__(message, 404)


class Conflict(TaskError):
    def __init__(self, message: str) -> None:
        super().__init__(message, 409)


FAILED_LIKE = {TaskStatus.FAILED, TaskStatus.CANCELLED, TaskStatus.TIMED_OUT}
SORT_KEYS = {"priority", "created_at", "updated_at", "deadline", "status", "title"}


class TaskService:
    def __init__(self, store: TaskStore, agent_names: Iterable[str], clock: Callable[[], float] = now) -> None:
        self.store = store
        self.agent_names = set(agent_names)
        self.clock = clock

    # ─── helpers ────────────────────────────────────────────────────────
    def _event(self, task: Task, type_: str, message: str, actor: str = "system", **data: Any) -> None:
        ev = task.log(type_, message, actor, **data)
        ev.ts = self.clock()
        task.updated_at = ev.ts
        self.store.add_event(ev)

    def _check_agent(self, name: str) -> None:
        if name not in self.agent_names:
            raise TaskError(f"unknown agent: {name}. Available: {', '.join(sorted(self.agent_names))}")

    def get(self, task_id: str) -> Task:
        task = self.store.get_task(task_id)
        if not task:
            raise NotFound(f"task {task_id} not found")
        return task

    def get_pair(self, pair_id: str) -> Pair:
        pair = self.store.get_pair(pair_id)
        if not pair:
            raise NotFound(f"pair {pair_id} not found")
        return pair

    def _build_assignments(
        self, agent: str | None, agents: list[str] | None, pair_id: str | None
    ) -> tuple[AssignmentMode, list[Assignment], str | None]:
        if pair_id is not None:
            pair = self.get_pair(pair_id)
            return AssignmentMode.PAIR, [Assignment(agent=pair.worker), Assignment(agent=pair.reviewer)], pair.id
        if agents:
            unique = list(dict.fromkeys(agents))
            for a in unique:
                self._check_agent(a)
            mode = AssignmentMode.MULTI if len(unique) > 1 else AssignmentMode.SINGLE
            return mode, [Assignment(agent=a) for a in unique], None
        if agent is None:
            raise TaskError("specify exactly one of: agent, agents, pair_id")
        self._check_agent(agent)
        return AssignmentMode.SINGLE, [Assignment(agent=agent)], None

    def _check_deps(self, task_id: str, deps: list[str]) -> list[str]:
        deps = list(dict.fromkeys(deps))
        if task_id in deps:
            raise TaskError("task cannot depend on itself")
        for d in deps:
            self.get(d)
        # cycle check: walking dependencies of deps must never reach task_id
        stack, seen = list(deps), set()
        while stack:
            cur = stack.pop()
            if cur == task_id:
                raise TaskError("dependency cycle detected")
            if cur in seen:
                continue
            seen.add(cur)
            t = self.store.get_task(cur)
            if t:
                stack.extend(t.depends_on)
        return deps

    def _evaluate_readiness(self, task: Task) -> None:
        """Move a PENDING/QUEUED task to QUEUED, PENDING or FAILED based on its dependencies."""
        if task.status not in (TaskStatus.PENDING, TaskStatus.QUEUED):
            return
        deps = [self.store.get_task(d) for d in task.depends_on]
        broken = [d for d in deps if d is None or d.status in FAILED_LIKE]
        if broken:
            self.store.remove_from_queues(task.id)
            task.status = TaskStatus.FAILED
            task.finished_at = self.clock()
            task.error = "dependency failed: " + ", ".join(d.id if d else "<deleted>" for d in broken)
            task.unread = True
            self._event(task, "failed", task.error)
            return
        if all(d.status == TaskStatus.DONE for d in deps):
            if task.status != TaskStatus.QUEUED:
                task.status = TaskStatus.QUEUED
                self._event(task, "queued", f"queued with priority {task.priority.value}")
            self.store.enqueue(task)
        else:
            self.store.remove_from_queues(task.id)
            if task.status != TaskStatus.PENDING:
                task.status = TaskStatus.PENDING
                self._event(task, "pending", "waiting for dependencies")

    def dependents(self, task_id: str) -> list[Task]:
        return [t for t in self.store.all_tasks() if task_id in t.depends_on]

    def propagate(self, task_id: str) -> None:
        """Called after a task reaches a terminal state: unblock or fail its dependents."""
        for dep in self.dependents(task_id):
            with self.store.lock(dep.id):
                fresh = self.store.get_task(dep.id)
                if fresh and fresh.status in (TaskStatus.PENDING, TaskStatus.QUEUED):
                    before = fresh.status
                    self._evaluate_readiness(fresh)
                    self.store.save_task(fresh)
                    if fresh.status == TaskStatus.FAILED and before != TaskStatus.FAILED:
                        self.propagate(fresh.id)

    # ─── tasks: CRUD ────────────────────────────────────────────────────
    def create(self, data: TaskCreate) -> Task:
        mode, assignments, pair_id = self._build_assignments(data.agent, data.agents, data.pair_id)
        created = self.clock()
        deadline = data.deadline
        if data.deadline_in_seconds:
            deadline = created + data.deadline_in_seconds
        if deadline is not None and deadline <= created:
            raise TaskError("deadline must be in the future")
        task = Task(
            title=data.title,
            description=data.description,
            priority=data.priority,
            mode=mode,
            assignments=assignments,
            pair_id=pair_id,
            tags=data.tags,
            deadline=deadline,
            timeout_seconds=data.timeout_seconds,
            max_retries=data.max_retries,
            retry_backoff_seconds=data.retry_backoff_seconds,
            created_by=data.created_by,
            created_at=created,
            updated_at=created,
        )
        task.depends_on = self._check_deps(task.id, data.depends_on)
        targets = ", ".join(task.agents) if mode != AssignmentMode.PAIR else f"pair {pair_id}"
        self._event(task, "created", f"created ({mode.value}) → {targets}", data.created_by, agents=task.agents)
        self._evaluate_readiness(task)
        self.store.save_task(task)
        return task

    def update(self, task_id: str, data: TaskUpdate) -> Task:
        with self.store.lock(task_id):
            task = self.get(task_id)
            if task.status in ACTIVE:
                raise Conflict("task is running; cancel it before editing")
            if task.status in TERMINAL and (
                data.agent or data.agents or data.pair_id or data.depends_on is not None
            ):
                raise Conflict("finished task: only title/description/priority/tags can change; use retry")
            changes: list[str] = []
            if data.title is not None and data.title != task.title:
                task.title = data.title
                changes.append("title")
            if data.description is not None and data.description != task.description:
                task.description = data.description
                changes.append("description")
            if data.priority is not None and data.priority != task.priority:
                changes.append(f"priority {task.priority.value}→{data.priority.value}")
                task.priority = data.priority
            if data.tags is not None:
                task.tags = sorted({t.strip().lower() for t in data.tags if t.strip()})
                changes.append("tags")
            if data.clear_deadline:
                task.deadline = None
                changes.append("deadline cleared")
            elif data.deadline is not None:
                if data.deadline <= self.clock():
                    raise TaskError("deadline must be in the future")
                task.deadline = data.deadline
                changes.append("deadline")
            if data.timeout_seconds is not None:
                task.timeout_seconds = data.timeout_seconds
                changes.append("timeout")
            if data.max_retries is not None:
                task.max_retries = data.max_retries
                changes.append("max_retries")
            if data.agent is not None or data.agents or data.pair_id is not None:
                if sum([data.agent is not None, bool(data.agents), data.pair_id is not None]) != 1:
                    raise TaskError("specify exactly one of: agent, agents, pair_id")
                task.mode, task.assignments, task.pair_id = self._build_assignments(
                    data.agent, data.agents, data.pair_id
                )
                task.pair_rounds = []
                changes.append("reassigned → " + ", ".join(task.agents))
            if data.depends_on is not None:
                task.depends_on = self._check_deps(task.id, data.depends_on)
                changes.append("dependencies")
            if not changes:
                return task
            self._event(task, "updated", "; ".join(changes), data.actor)
            if task.status == TaskStatus.QUEUED:
                self.store.enqueue(task)  # refresh priority score
            self._evaluate_readiness(task)
            self.store.save_task(task)
        if task.status == TaskStatus.FAILED:
            self.propagate(task.id)
        return task

    def cancel(self, task_id: str, actor: str = "user", reason: str = "") -> Task:
        with self.store.lock(task_id):
            task = self.get(task_id)
            if task.status in TERMINAL:
                raise Conflict(f"task already {task.status.value}")
            self.store.remove_from_queues(task_id)
            task.status = TaskStatus.CANCELLED
            task.finished_at = self.clock()
            task.error = reason or "cancelled"
            self._event(task, "cancelled", reason or "cancelled", actor)
            self.store.save_task(task)
        self.propagate(task_id)
        return task

    def retry(self, task_id: str, actor: str = "user") -> Task:
        with self.store.lock(task_id):
            task = self.get(task_id)
            if task.status not in FAILED_LIKE:
                raise Conflict("only failed, cancelled or timed out tasks can be retried")
            if task.deadline is not None and task.deadline <= self.clock():
                task.deadline = None
            task.status = TaskStatus.PENDING
            task.attempts = 0
            task.error = None
            task.result = None
            task.finished_at = None
            task.pair_rounds = []
            for a in task.assignments:
                a.status, a.result, a.error = AssignmentStatus.PENDING, None, None
            self._event(task, "retry", "manual retry", actor)
            self._evaluate_readiness(task)
            self.store.save_task(task)
        return task

    def delete(self, task_id: str) -> None:
        task = self.get(task_id)
        if task.status in ACTIVE:
            raise Conflict("task is running; cancel it first")
        blocking = [t.id for t in self.dependents(task_id) if t.status not in TERMINAL]
        if blocking:
            raise Conflict("other tasks depend on it: " + ", ".join(blocking))
        self.store.delete_task(task_id)
        self.store.add_event(Event(task_id=task_id, type="deleted", message=f"task '{task.title}' deleted"))

    def add_comment(self, task_id: str, data: CommentCreate) -> Comment:
        with self.store.lock(task_id):
            task = self.get(task_id)
            comment = Comment(author=data.author, text=data.text, ts=self.clock())
            task.comments.append(comment)
            self._event(task, "comment", data.text[:200], data.author)
            self.store.save_task(task)
        return comment

    def mark_read(self, task_id: str) -> Task:
        with self.store.lock(task_id):
            task = self.get(task_id)
            task.unread = False
            self.store.save_task(task)
        return task

    # ─── listing ────────────────────────────────────────────────────────
    def list(
        self,
        *,
        status: list[TaskStatus] | None = None,
        priority: list[Priority] | None = None,
        agent: str | None = None,
        pair_id: str | None = None,
        tag: str | None = None,
        q: str | None = None,
        unread: bool | None = None,
        overdue: bool | None = None,
        sort: str = "priority",
        order: str = "desc",
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[int, list[Task]]:
        if sort not in SORT_KEYS:
            raise TaskError(f"sort must be one of {sorted(SORT_KEYS)}")
        ts = self.clock()
        items = self.store.all_tasks()
        if status:
            items = [t for t in items if t.status in status]
        if priority:
            items = [t for t in items if t.priority in priority]
        if agent:
            items = [t for t in items if agent in t.agents]
        if pair_id:
            items = [t for t in items if t.pair_id == pair_id]
        if tag:
            items = [t for t in items if tag.lower() in t.tags]
        if q:
            needle = q.lower()
            items = [
                t
                for t in items
                if needle in t.title.lower()
                or needle in t.description.lower()
                or any(needle in c.text.lower() for c in t.comments)
            ]
        if unread is not None:
            items = [t for t in items if t.unread == unread]
        if overdue is not None:
            items = [
                t
                for t in items
                if (t.deadline is not None and t.deadline < ts and t.status not in TERMINAL) == overdue
            ]

        def key(t: Task) -> Any:
            if sort == "priority":
                return (t.priority.rank, -t.created_at)
            if sort == "deadline":
                return t.deadline if t.deadline is not None else float("inf")
            if sort == "status":
                return t.status.value
            if sort == "title":
                return t.title.lower()
            return getattr(t, sort)

        items.sort(key=key, reverse=(order == "desc"))
        if sort == "deadline" and order == "desc":
            items = [t for t in items if t.deadline is not None] + [t for t in items if t.deadline is None]
        return len(items), items[offset : offset + limit]

    def agent_overview(self) -> list[dict[str, Any]]:
        tasks = self.store.all_tasks()
        out = []
        for name in sorted(self.agent_names):
            mine = [t for t in tasks if name in t.agents]
            counts: dict[str, int] = {}
            for t in mine:
                counts[t.status.value] = counts.get(t.status.value, 0) + 1
            out.append(
                {
                    "agent": name,
                    "total": len(mine),
                    "by_status": counts,
                    "active": sum(1 for t in mine if t.status in ACTIVE),
                    "unread": sum(1 for t in mine if t.unread),
                    "pairs": [p.id for p in self.store.all_pairs() if name in (p.worker, p.reviewer)],
                }
            )
        return out

    def stats(self) -> dict[str, Any]:
        tasks = self.store.all_tasks()
        by_status: dict[str, int] = {}
        by_priority: dict[str, int] = {}
        for t in tasks:
            by_status[t.status.value] = by_status.get(t.status.value, 0) + 1
            by_priority[t.priority.value] = by_priority.get(t.priority.value, 0) + 1
        ts = self.clock()
        return {
            "total": len(tasks),
            "by_status": by_status,
            "by_priority": by_priority,
            "queue_length": len(self.store.queued_ids()),
            "overdue": sum(1 for t in tasks if t.deadline and t.deadline < ts and t.status not in TERMINAL),
            "unread": sum(1 for t in tasks if t.unread),
        }

    # ─── pairs ──────────────────────────────────────────────────────────
    def create_pair(self, data: PairCreate) -> Pair:
        self._check_agent(data.worker)
        self._check_agent(data.reviewer)
        try:
            pair = Pair(**data.model_dump(), created_at=self.clock())
        except ValueError as exc:
            raise TaskError(str(exc)) from exc
        self.store.save_pair(pair)
        self.store.add_event(Event(type="pair_created", message=f"pair {pair.name}: {pair.worker} + {pair.reviewer}"))
        return pair

    def _tasks_using_pair(self, pair_id: str) -> list[Task]:
        return [t for t in self.store.all_tasks() if t.pair_id == pair_id]

    def update_pair(self, pair_id: str, data: PairUpdate) -> Pair:
        pair = self.get_pair(pair_id)
        if any(t.status in ACTIVE for t in self._tasks_using_pair(pair_id)):
            raise Conflict("pair is working on a task right now")
        fields = data.model_dump(exclude_none=True)
        for name in ("worker", "reviewer"):
            if name in fields:
                self._check_agent(fields[name])
        try:
            pair = Pair(**{**pair.model_dump(), **fields})
        except ValueError as exc:
            raise TaskError(str(exc)) from exc
        self.store.save_pair(pair)
        # keep not-yet-started tasks of this pair in sync with the new members
        for t in self._tasks_using_pair(pair_id):
            if t.status in (TaskStatus.PENDING, TaskStatus.QUEUED, TaskStatus.RETRY_WAIT):
                with self.store.lock(t.id):
                    fresh = self.get(t.id)
                    fresh.assignments = [Assignment(agent=pair.worker), Assignment(agent=pair.reviewer)]
                    self._event(fresh, "updated", f"pair members changed → {pair.worker}, {pair.reviewer}")
                    self.store.save_task(fresh)
        self.store.add_event(Event(type="pair_updated", message=f"pair {pair.name} updated"))
        return pair

    def delete_pair(self, pair_id: str) -> None:
        self.get_pair(pair_id)
        busy = [t.id for t in self._tasks_using_pair(pair_id) if t.status not in TERMINAL]
        if busy:
            raise Conflict("pair has unfinished tasks: " + ", ".join(busy))
        self.store.delete_pair(pair_id)
        self.store.add_event(Event(type="pair_deleted", message=f"pair {pair_id} deleted"))
