import asyncio
import base64
import json
import ssl
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import geo  # noqa: E402
import health  # noqa: E402
import main  # noqa: E402


def node(i: int, host: str | None = None, typ: str = "vless", country: str = "DE", port: int = 443, score: int = 50):
    return {"type": typ, "host": host or f"h{i}.example.com", "port": port, "dedup_key": f"k{i}", "score": score,
            "country": country, "is_tls": True, "sni": f"h{i}.example.com", "best_for": "lte", "name": f"n{i}",
            "raw": f"vless://u{i}@h{i}.example.com:{port}?security=tls&sni=h{i}.example.com#n{i}",
            "params": {}, "is_reality": False, "uuid": f"u{i}"}


def mark(c: dict, alive: bool | None, ms: float | None = 100, cert_ok=None):
    health._health[c["dedup_key"]] = {"alive": alive, "ms": ms, "method": "tls", "ts": time.time(), "cert_ok": cert_ok}


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    health.clear()
    monkeypatch.setenv("DISABLE_BACKGROUND", "1")
    yield
    health.clear()


# ------------------------------------------------------------ selection
def test_select_drops_dead_and_sorts_by_latency():
    a, b, c, d = (node(i, score=50) for i in range(4))
    mark(a, True, 500)
    mark(b, True, 50)
    mark(c, False, None)
    # d has no health record: excluded once health data exists
    out = main.select_nodes([a, b, c, d], max_configs=10)
    assert [x["dedup_key"] for x in out] == ["k1", "k0"]


def test_select_without_any_health_keeps_everything():
    out = main.select_nodes([node(1), node(2)], max_configs=10)
    assert len(out) == 2


def test_select_caps_per_host_and_per_country():
    ns = [node(i, host="same.example.com") for i in range(5)] + [node(10 + i, country="US") for i in range(10)]
    for c in ns:
        mark(c, True, 10)
    out = main.select_nodes(ns, max_configs=10)
    assert sum(1 for c in out if c["host"] == "same.example.com") <= main.MAX_PER_HOST
    assert sum(1 for c in out if c["country"] == "DE") <= 4  # 40% of 10
    assert sum(1 for c in out if c["country"] == "US") <= 4


def test_select_filters_protocol_and_country():
    ns = [node(1, typ="trojan"), node(2, typ="vless", country="NL"), node(3, typ="vless", country="DE")]
    for c in ns:
        mark(c, True)
    assert [c["dedup_key"] for c in main.select_nodes(ns, protocols={"trojan"})] == ["k1"]
    assert [c["dedup_key"] for c in main.select_nodes(ns, countries={"NL"})] == ["k2"]


def test_udp_nodes_get_reserved_but_limited_share():
    tcp = [node(i) for i in range(30)]
    udp = [node(100 + i, typ="hysteria2", country=["US", "FR", "JP", "SG", "GB"][i % 5]) for i in range(30)]
    for c in tcp:
        mark(c, True, 10)
    for c in udp:
        mark(c, None, None)
    out = main.select_nodes(tcp + udp, max_configs=20)
    n_udp = sum(1 for c in out if c["type"] == "hysteria2")
    assert 2 <= n_udp <= max(2, 20 * main.UDP_SLOTS_PERCENT // 100)
    only = main.select_nodes(tcp + udp, max_configs=20, protocols={"hysteria2"})
    assert len(only) == 20 and all(c["type"] == "hysteria2" for c in only)


def test_select_marks_cert_ok_from_health():
    c = node(1)
    mark(c, True, 10, cert_ok=False)
    out = main.select_nodes([c], max_configs=5)
    assert out[0]["cert_ok"] is False


# ------------------------------------------------------------ health
def test_probe_method_by_type():
    assert health.probe_method({"type": "hysteria2"}) == "none"
    assert health.probe_method({"type": "tuic"}) == "none"
    assert health.probe_method({"type": "vless", "is_reality": True}) == "tls"
    assert health.probe_method({"type": "ss"}) == "tcp"


def test_check_nodes_with_fake_checker_and_summary():
    ns = [node(i) for i in range(4)]

    async def fake(c, timeout):
        ok = int(c["dedup_key"][1:]) % 2 == 0
        return {"alive": ok, "ms": 10.0 * (int(c["dedup_key"][1:]) + 1) if ok else None, "method": "tls",
                "ts": time.time()}

    asyncio.run(health.check_nodes(ns, concurrency=2, checker=fake))
    s = health.summary(ns)
    assert (s["alive"], s["dead"], s["total"]) == (2, 2, 4)
    assert s["latency_ms_median"] in (10.0, 30.0)
    assert not any(health.needs_check(c) for c in ns)


def test_health_ttl_expiry():
    c = node(1)
    mark(c, True)
    health._health["k1"]["ts"] = time.time() - health.HEALTH_TTL - 5
    assert health.needs_check(c)
    assert health.get(c, max_age=health.HEALTH_TTL * 100) is not None


def test_real_tls_handshake_against_local_server(tmp_path):
    import subprocess
    key, crt = tmp_path / "k.pem", tmp_path / "c.pem"
    r = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(crt),
                        "-days", "1", "-subj", "/CN=localhost"], capture_output=True)
    if r.returncode != 0:
        pytest.skip("openssl not available")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)

    async def run():
        server = await asyncio.start_server(lambda rd, wr: wr.close(), "127.0.0.1", 0, ssl=ctx)
        port = server.sockets[0].getsockname()[1]
        good = await health.tls_handshake("127.0.0.1", port, "localhost", 3, verify=True)
        plain = await health.tls_handshake("127.0.0.1", port, "localhost", 3)
        dead = await health.tls_handshake("127.0.0.1", 1, "localhost", 1)
        server.close()
        await server.wait_closed()
        return good, plain, dead

    good, plain, dead = asyncio.run(run())
    assert good[0] is not None and good[1] is False  # self-signed: alive but the certificate does not validate
    assert plain[0] is not None and plain[1] is None
    assert dead == (None, None)


# ------------------------------------------------------------ geo
def test_annotate_countries_uses_name_flag_then_lookup(monkeypatch):
    async def fake_resolve(host):
        return {"a.example.com": "1.1.1.1", "b.example.com": "2.2.2.2"}.get(host)

    async def fake_lookup(ips, client=None):
        return {"2.2.2.2": "JP"}

    monkeypatch.setattr(geo, "_resolve_ip", fake_resolve)
    monkeypatch.setattr(geo, "lookup_ips", fake_lookup)
    ns = [{"host": "a.example.com", "name": "🇫🇷 paris"}, {"host": "b.example.com", "name": "x"},
          {"host": "c.example.com", "name": "y"}]
    asyncio.run(geo.annotate_countries(ns))
    assert [n.get("country") for n in ns] == ["FR", "JP", None]


# ------------------------------------------------------------ routes
@pytest.fixture
def client(monkeypatch):
    from fastapi.testclient import TestClient

    ns = [node(i, country=["DE", "NL", "US", "FR", "DE", "JP"][i % 6]) for i in range(8)]
    for c in ns:
        mark(c, True, 20 + 10 * int(c["dedup_key"][1:]), cert_ok=True)

    async def fake_fetch(force=False):
        return ns

    async def noop(*a, **k):
        return 0

    monkeypatch.setattr(main, "fetch_configs", fake_fetch)
    monkeypatch.setattr(main, "ensure_health", noop)
    monkeypatch.setattr(geo, "annotate_countries", noop)
    return TestClient(main.app)


def test_sub_headers_and_default_base64(client):
    r = client.get("/sub", headers={"User-Agent": "v2rayNG/1.9"})
    assert r.status_code == 200
    for key in ("profile-title", "profile-update-interval", "subscription-userinfo", "support-url", "announce",
                "routing", "content-disposition", "profile-web-page-url"):
        assert r.headers.get(key), key
    assert r.headers["x-format"] == "base64" and r.headers["x-nodes"] == "8"
    assert "vless://" in base64.b64decode(r.text).decode()
    assert r.headers["routing"].startswith("happ://routing/onadd/")


@pytest.mark.parametrize("ua,fmt,ctype", [
    ("clash.meta/1.18", "clash", "yaml"), ("sing-box 1.12", "singbox", "json"),
    ("Mozilla/5.0 Chrome/120", "uri", "text/plain"),
])
def test_sub_negotiates_format_by_user_agent(client, ua, fmt, ctype):
    r = client.get("/sub", headers={"User-Agent": ua})
    assert r.status_code == 200 and r.headers["x-format"] == fmt
    assert ctype in r.headers["content-type"]


def test_sub_explicit_format_xray_and_filters(client):
    r = client.get("/sub?format=xray&country=DE")
    assert r.status_code == 200
    cfgs = json.loads(r.text)
    assert cfgs and all("Германия" in c["remarks"] for c in cfgs)
    assert client.get("/sub?format=bogus").status_code == 422


def test_sub_503_when_nothing_matches(client):
    r = client.get("/sub?country=ZZ")
    assert r.status_code == 503 and r.headers["retry-after"] == "30"


def test_sub_head_and_variants(client):
    assert client.head("/sub").status_code == 200
    for path in ("/sub/lte", "/sub/3g", "/sub/wifi", "/sub/best"):
        assert client.get(path).status_code in (200, 503)


def test_stats_and_health_endpoints(client):
    s = client.get("/stats").json()
    assert s["total_configs"] == 8 and s["by_country"]["DE"] == 3
    assert s["health"]["alive"] == 8 and "clash" in s["formats"]
    h = client.get("/health").json()
    assert h["status"] == "ok" and h["pool"]["alive"] == 8
