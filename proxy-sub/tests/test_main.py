import asyncio
import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import main  # noqa: E402

VLESS = (
    "vless://uuid-1@example.com:443?security=reality&type=tcp&flow=xtls-rprx-vision"
    "&sni=www.yandex.ru&fp=chrome&pbk=KEY&sid=ab#My%20node"
)


def test_parse_vless_reality_vision():
    c = main.parse_vless(VLESS)
    assert c["host"] == "example.com" and c["port"] == 443
    assert c["is_reality"] and c["is_vision"] and c["best_for"] == "lte"
    assert c["name"] == "My node"


def test_parse_ss_sip002_base64_with_plugin():
    user = base64.urlsafe_b64encode(b"aes-256-gcm:pass").decode().rstrip("=")
    c = main.parse_ss(f"ss://{user}@1.2.3.4:8443/?plugin=v2ray-plugin#x")
    assert (c["method"], c["host"], c["port"]) == ("aes-256-gcm", "1.2.3.4", 8443)


def test_parse_ss_plain_userinfo():
    c = main.parse_ss("ss://chacha20-ietf-poly1305:secret@host.example:443#n")
    assert c["method"] == "chacha20-ietf-poly1305" and c["port"] == 443


def test_parse_ss_legacy_full_base64():
    enc = base64.b64encode(b"aes-128-gcm:pw@5.6.7.8:2053").decode()
    c = main.parse_ss(f"ss://{enc}#legacy")
    assert c["host"] == "5.6.7.8" and c["port"] == 2053


def test_decode_source_base64_with_newlines_and_bom():
    payload = base64.b64encode((VLESS + "\n").encode()).decode()
    wrapped = "\ufeff" + "\n".join(payload[i:i + 40] for i in range(0, len(payload), 40))
    assert main.decode_source(wrapped).startswith("vless://")
    assert main.decode_source("  " + VLESS).startswith("vless://")


def test_build_subscription_filters_and_limits():
    configs = [main.parse_vless(VLESS), main.parse_vless(VLESS.replace(":443", ":9999").replace("uuid-1", "u2"))]
    text = main.build_subscription(configs, network="lte", max_configs=10)
    lines = [ln for ln in text.splitlines() if ln.startswith("vless://")]
    assert len(lines) == 1 and lines[0].endswith(":443")
    assert "//profile-title: base64:" in text


def test_tcp_ping_real_socket():
    async def run():
        server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        ok = await main.tcp_ping("127.0.0.1", port, timeout=2)
        server.close()
        await server.wait_closed()
        bad = await main.tcp_ping("127.0.0.1", 1, timeout=1)
        return ok, bad

    ok, bad = asyncio.run(run())
    assert ok is not None and ok >= 0
    assert bad is None


def test_fetch_keeps_previous_configs_when_sources_fail(monkeypatch):
    main._cache.update(configs=[{"dedup_key": "x", "score": 1}], last_update=0)

    class Failing:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url):
            raise OSError("network down")

    monkeypatch.setattr(main.httpx, "AsyncClient", Failing)
    got = asyncio.run(main.fetch_configs(force=True))
    assert got == [{"dedup_key": "x", "score": 1}]


def test_refresh_token(monkeypatch):
    from fastapi.testclient import TestClient

    async def fake_fetch(force=False):
        return []

    monkeypatch.setattr(main, "fetch_configs", fake_fetch)
    monkeypatch.setenv("REFRESH_TOKEN", "t")
    c = TestClient(main.app)
    assert c.post("/refresh").status_code == 403
    assert c.post("/refresh", headers={"X-Refresh-Token": "t"}).json()["status"] == "ok"
