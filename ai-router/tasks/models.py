from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


def now() -> float:
    return time.time()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class Priority(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2, "critical": 3}[self.value]


class TaskStatus(str, Enum):
    PENDING = "pending"  # created, waiting for dependencies
    QUEUED = "queued"  # in priority queue
    RUNNING = "running"  # agent(s) working
    REVIEW = "review"  # pair reviewer is checking the worker's output
    RETRY_WAIT = "retry_wait"  # failed attempt, waiting for backoff
    DONE = "done"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


TERMINAL = {TaskStatus.DONE, TaskStatus.FAILED, TaskStatus.CANCELLED, TaskStatus.TIMED_OUT}
ACTIVE = {TaskStatus.RUNNING, TaskStatus.REVIEW}


class AssignmentMode(str, Enum):
    SINGLE = "single"  # one agent
    MULTI = "multi"  # several agents, each does the task individually
    PAIR = "pair"  # worker + reviewer iterate


class AssignmentStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


class Assignment(BaseModel):
    agent: str
    status: AssignmentStatus = AssignmentStatus.PENDING
    result: str | None = None
    error: str | None = None
    started_at: float | None = None
    finished_at: float | None = None


class Event(BaseModel):
    ts: float = Field(default_factory=now)
    task_id: str | None = None
    type: str
    message: str
    actor: str = "system"
    data: dict[str, Any] = Field(default_factory=dict)


class Comment(BaseModel):
    id: str = Field(default_factory=lambda: new_id("c"))
    ts: float = Field(default_factory=now)
    author: str = "user"
    text: str


class Pair(BaseModel):
    id: str = Field(default_factory=lambda: new_id("pair"))
    name: str
    worker: str
    reviewer: str
    max_rounds: int = Field(3, ge=1, le=10)
    description: str = ""
    created_at: float = Field(default_factory=now)

    @model_validator(mode="after")
    def _distinct(self) -> Pair:
        if self.worker == self.reviewer:
            raise ValueError("worker and reviewer must be different agents")
        return self


class PairRound(BaseModel):
    round: int
    work: str
    review: str
    approved: bool


class Task(BaseModel):
    id: str = Field(default_factory=lambda: new_id("task"))
    title: str
    description: str = ""
    priority: Priority = Priority.MEDIUM
    status: TaskStatus = TaskStatus.PENDING
    mode: AssignmentMode
    assignments: list[Assignment] = Field(default_factory=list)
    pair_id: str | None = None
    pair_rounds: list[PairRound] = Field(default_factory=list)
    approved: bool | None = None
    depends_on: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    deadline: float | None = None  # unix ts; task is timed out if not finished by then
    timeout_seconds: float = Field(300, gt=0)  # per attempt
    max_retries: int = Field(2, ge=0, le=10)
    attempts: int = 0
    retry_backoff_seconds: float = Field(5, ge=0)
    next_attempt_at: float | None = None
    result: str | None = None
    error: str | None = None
    created_by: str = "user"
    created_at: float = Field(default_factory=now)
    updated_at: float = Field(default_factory=now)
    started_at: float | None = None
    finished_at: float | None = None
    comments: list[Comment] = Field(default_factory=list)
    history: list[Event] = Field(default_factory=list)
    unread: bool = False  # set when a task finishes; cleared when someone reads it

    @property
    def agents(self) -> list[str]:
        return [a.agent for a in self.assignments]

    def log(self, type_: str, message: str, actor: str = "system", **data: Any) -> Event:
        ev = Event(task_id=self.id, type=type_, message=message, actor=actor, data=data)
        self.history.append(ev)
        self.updated_at = ev.ts
        return ev


# ─── API payloads ───────────────────────────────────────────────────────────


class TaskCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: str = ""
    priority: Priority = Priority.MEDIUM
    agent: str | None = None  # single
    agents: list[str] | None = None  # multi (each individually)
    pair_id: str | None = None  # pair
    depends_on: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    deadline: float | None = None
    deadline_in_seconds: float | None = Field(None, gt=0)
    timeout_seconds: float = Field(300, gt=0, le=3600)
    max_retries: int = Field(2, ge=0, le=10)
    retry_backoff_seconds: float = Field(5, ge=0, le=3600)
    created_by: str = "user"

    @model_validator(mode="after")
    def _one_target(self) -> TaskCreate:
        targets = [self.agent is not None, bool(self.agents), self.pair_id is not None]
        if sum(targets) != 1:
            raise ValueError("specify exactly one of: agent, agents, pair_id")
        return self

    @field_validator("tags")
    @classmethod
    def _tags(cls, v: list[str]) -> list[str]:
        return sorted({t.strip().lower() for t in v if t.strip()})


class TaskUpdate(BaseModel):
    title: str | None = Field(None, min_length=1, max_length=200)
    description: str | None = None
    priority: Priority | None = None
    agent: str | None = None
    agents: list[str] | None = None
    pair_id: str | None = None
    depends_on: list[str] | None = None
    tags: list[str] | None = None
    deadline: float | None = None
    clear_deadline: bool = False
    timeout_seconds: float | None = Field(None, gt=0, le=3600)
    max_retries: int | None = Field(None, ge=0, le=10)
    actor: str = "user"


class PairCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    worker: str
    reviewer: str
    max_rounds: int = Field(3, ge=1, le=10)
    description: str = ""


class PairUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=100)
    worker: str | None = None
    reviewer: str | None = None
    max_rounds: int | None = Field(None, ge=1, le=10)
    description: str | None = None


class CommentCreate(BaseModel):
    text: str = Field(min_length=1, max_length=5000)
    author: str = "user"
