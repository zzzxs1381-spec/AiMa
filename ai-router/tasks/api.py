"""HTTP API for the task system (FastAPI)."""

from __future__ import annotations

import hmac
import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from tasks.models import (
    CommentCreate,
    PairCreate,
    PairUpdate,
    Priority,
    TaskCreate,
    TaskStatus,
    TaskUpdate,
)
from tasks.service import TaskError, TaskService


def create_app(
    service: TaskService,
    *,
    api_token: str | None = None,
    read_token: str | None = None,
    worker: Any = None,
) -> FastAPI:
    """Build the API.

    Permissions: if AI_ROUTER_API_TOKEN is set, every write requires `X-API-Key: <token>`.
    If AI_ROUTER_READ_TOKEN is set, reads require either the read or the admin token.
    """
    api_token = api_token if api_token is not None else os.environ.get("AI_ROUTER_API_TOKEN", "")
    read_token = read_token if read_token is not None else os.environ.get("AI_ROUTER_READ_TOKEN", "")
    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        if worker is not None:
            worker.start()
        try:
            yield
        finally:
            if worker is not None:
                worker.stop()

    app = FastAPI(title="AI Router — Task System", lifespan=lifespan)

    def _match(given: str | None, expected: str) -> bool:
        return bool(expected) and given is not None and hmac.compare_digest(given, expected)

    def can_write(x_api_key: str | None = Header(None)) -> None:
        if api_token and not _match(x_api_key, api_token):
            raise HTTPException(401, "write access requires a valid X-API-Key")

    def can_read(x_api_key: str | None = Header(None)) -> None:
        if read_token and not (_match(x_api_key, read_token) or _match(x_api_key, api_token)):
            raise HTTPException(401, "read access requires a valid X-API-Key")

    @app.exception_handler(TaskError)
    async def _task_error(_req: Request, exc: TaskError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"detail": str(exc)})

    R = [Depends(can_read)]
    W = [Depends(can_write)]

    @app.get("/health")
    def health() -> dict[str, Any]:
        service.store.r.ping()
        return {"ok": True}

    # agents
    @app.get("/agents", dependencies=R)
    def agents() -> list[dict[str, Any]]:
        return service.agent_overview()

    # tasks
    @app.post("/tasks", status_code=201, dependencies=W)
    def create_task(data: TaskCreate) -> dict[str, Any]:
        return service.create(data).model_dump(mode="json")

    @app.get("/tasks", dependencies=R)
    def list_tasks(
        status: list[TaskStatus] | None = Query(None),
        priority: list[Priority] | None = Query(None),
        agent: str | None = None,
        pair_id: str | None = None,
        tag: str | None = None,
        q: str | None = None,
        unread: bool | None = None,
        overdue: bool | None = None,
        sort: str = "priority",
        order: str = Query("desc", pattern="^(asc|desc)$"),
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0),
    ) -> dict[str, Any]:
        total, items = service.list(
            status=status, priority=priority, agent=agent, pair_id=pair_id, tag=tag, q=q,
            unread=unread, overdue=overdue, sort=sort, order=order, limit=limit, offset=offset,
        )
        return {"total": total, "items": [t.model_dump(mode="json", exclude={"history"}) for t in items]}

    @app.get("/tasks/stats", dependencies=R)
    def task_stats() -> dict[str, Any]:
        return service.stats()

    @app.get("/tasks/{task_id}", dependencies=R)
    def get_task(task_id: str) -> dict[str, Any]:
        return service.get(task_id).model_dump(mode="json")

    @app.patch("/tasks/{task_id}", dependencies=W)
    def update_task(task_id: str, data: TaskUpdate) -> dict[str, Any]:
        return service.update(task_id, data).model_dump(mode="json")

    @app.post("/tasks/{task_id}/cancel", dependencies=W)
    def cancel_task(task_id: str, reason: str = "", actor: str = "user") -> dict[str, Any]:
        return service.cancel(task_id, actor=actor, reason=reason).model_dump(mode="json")

    @app.post("/tasks/{task_id}/retry", dependencies=W)
    def retry_task(task_id: str, actor: str = "user") -> dict[str, Any]:
        return service.retry(task_id, actor=actor).model_dump(mode="json")

    @app.post("/tasks/{task_id}/read", dependencies=W)
    def read_task(task_id: str) -> dict[str, Any]:
        return service.mark_read(task_id).model_dump(mode="json")

    @app.delete("/tasks/{task_id}", status_code=204, dependencies=W)
    def delete_task(task_id: str) -> None:
        service.delete(task_id)

    @app.post("/tasks/{task_id}/comments", status_code=201, dependencies=W)
    def add_comment(task_id: str, data: CommentCreate) -> dict[str, Any]:
        return service.add_comment(task_id, data).model_dump(mode="json")

    @app.get("/tasks/{task_id}/history", dependencies=R)
    def task_history(task_id: str) -> list[dict[str, Any]]:
        return [e.model_dump(mode="json") for e in service.get(task_id).history]

    # pairs
    @app.get("/pairs", dependencies=R)
    def list_pairs() -> list[dict[str, Any]]:
        return [p.model_dump(mode="json") for p in service.store.all_pairs()]

    @app.post("/pairs", status_code=201, dependencies=W)
    def create_pair(data: PairCreate) -> dict[str, Any]:
        return service.create_pair(data).model_dump(mode="json")

    @app.get("/pairs/{pair_id}", dependencies=R)
    def get_pair(pair_id: str) -> dict[str, Any]:
        return service.get_pair(pair_id).model_dump(mode="json")

    @app.patch("/pairs/{pair_id}", dependencies=W)
    def update_pair(pair_id: str, data: PairUpdate) -> dict[str, Any]:
        return service.update_pair(pair_id, data).model_dump(mode="json")

    @app.delete("/pairs/{pair_id}", status_code=204, dependencies=W)
    def delete_pair(pair_id: str) -> None:
        service.delete_pair(pair_id)

    # activity log
    @app.get("/events", dependencies=R)
    def events(limit: int = Query(100, ge=1, le=1000), task_id: str | None = None, agent: str | None = None):
        return [e.model_dump(mode="json") for e in service.store.events(limit=limit, task_id=task_id, agent=agent)]

    return app
