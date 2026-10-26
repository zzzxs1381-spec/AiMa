from fastapi.testclient import TestClient

from tasks.api import create_app


def test_api_crud_and_permissions(service, engine):
    client = TestClient(create_app(service, api_token="secret", read_token=""))
    payload = {"title": "Review PR", "agent": "validator", "priority": "high"}
    assert client.post("/tasks", json=payload).status_code == 401
    h = {"X-API-Key": "secret"}
    r = client.post("/tasks", json=payload, headers=h)
    assert r.status_code == 201
    tid = r.json()["id"]
    assert client.post("/tasks", json={"title": "x"}, headers=h).status_code == 422
    assert client.post("/tasks", json={"title": "x", "agent": "ghost"}, headers=h).status_code == 400

    pair = client.post("/pairs", json={"name": "duo", "worker": "coder", "reviewer": "validator"}, headers=h).json()
    r = client.post("/tasks", json={"title": "pair job", "pair_id": pair["id"]}, headers=h)
    assert r.json()["mode"] == "pair"

    r = client.get("/tasks", params={"priority": "high"})
    assert r.json()["total"] == 1 and r.json()["items"][0]["id"] == tid
    assert client.patch(f"/tasks/{tid}", json={"priority": "critical"}, headers=h).json()["priority"] == "critical"
    assert client.post(f"/tasks/{tid}/comments", json={"text": "urgent"}, headers=h).status_code == 201

    engine.run_until_idle()
    t = client.get(f"/tasks/{tid}").json()
    assert t["status"] == "done" and t["unread"] is True
    assert client.get("/tasks", params={"unread": True}).json()["total"] == 2
    assert client.post(f"/tasks/{tid}/cancel", headers=h).status_code == 409
    assert any(e["type"] == "comment" for e in client.get(f"/tasks/{tid}/history").json())
    assert client.get("/tasks/stats").json()["total"] == 2
    assert {a["agent"] for a in client.get("/agents").json()} >= {"coder", "validator"}
    assert client.get("/events", params={"task_id": tid}).json()
    assert client.delete(f"/tasks/{tid}", headers=h).status_code == 204
    assert client.get(f"/tasks/{tid}").status_code == 404


def test_read_token(service):
    client = TestClient(create_app(service, api_token="w", read_token="r"))
    assert client.get("/tasks").status_code == 401
    assert client.get("/tasks", headers={"X-API-Key": "r"}).status_code == 200
    assert client.get("/tasks", headers={"X-API-Key": "w"}).status_code == 200
    assert client.post("/pairs", json={"name": "p", "worker": "coder", "reviewer": "analyst"},
                       headers={"X-API-Key": "r"}).status_code == 401
