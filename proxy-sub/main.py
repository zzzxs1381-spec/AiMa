"""
Proxy Subscription Service for Hiddify
Auto-fetches, filters, and serves optimized VLESS/SS configs
Supports LTE/3G/Wi-Fi with auto-switching
"""

import asyncio
import base64
import hashlib
import os
import pathlib
import time
from datetime import datetime, timezone
from urllib.parse import unquote

import httpx
from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="Proxy Subscription Service")

# === CONFIG SOURCES ===
SOURCES = [
    "https://raw.githubusercontent.com/4n0nymou3/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs.txt",
    "https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/refs/heads/main/Reality",
    "https://raw.githubusercontent.com/dakrdevo/V2Ray-Subscription/main/Sub",
    "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/xray/normal/vless",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.txt",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt",
]

# Cache
_cache: dict = {"configs": [], "last_update": 0, "raw_text": ""}
CACHE_TTL = 3600  # 1 hour

# Ports known to work on LTE/3G
LTE_SAFE_PORTS = {443, 2053, 2083, 2087, 2096, 8443, 8080, 80}
# Best ports for mobile operators
PRIORITY_PORTS = {443, 8443, 2053, 2096}


def parse_vless(line: str) -> dict | None:
    """Parse a vless:// URI into a structured dict."""
    line = line.strip()
    if not line.startswith("vless://"):
        return None
    try:
        # Extract fragment (name)
        if "#" in line:
            uri_part, fragment = line.rsplit("#", 1)
            name = unquote(fragment).strip()
        else:
            uri_part = line
            name = ""

        # Parse UUID and server
        rest = uri_part[8:]  # remove vless://
        if "@" not in rest:
            return None
        uuid_part, server_part = rest.split("@", 1)

        # Parse server:port
        if "?" in server_part:
            host_port, params_str = server_part.split("?", 1)
        else:
            host_port = server_part
            params_str = ""

        # Handle IPv6
        if host_port.startswith("["):
            bracket_end = host_port.index("]")
            host = host_port[1:bracket_end]
            port_str = host_port[bracket_end + 2:]  # skip ]:
        else:
            parts = host_port.rsplit(":", 1)
            host = parts[0].rstrip("/")
            port_str = parts[1].rstrip("/") if len(parts) > 1 else "443"

        port = int(port_str)

        # Parse query params
        params = {}
        if params_str:
            for kv in params_str.split("&"):
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    params[k] = unquote(v)

        security = params.get("security", "none")
        transport = params.get("type", "tcp")
        flow = params.get("flow", "")
        sni = params.get("sni", "")
        fp = params.get("fp", "")
        pbk = params.get("pbk", "")
        sid = params.get("sid", "")

        # Determine config type
        is_reality = security == "reality"
        is_vision = "vision" in flow
        is_tls = security == "tls"
        is_ws = transport == "ws"
        is_grpc = transport == "grpc"

        # Calculate quality score
        score = 0
        # REALITY + VISION = best for LTE
        if is_reality and is_vision:
            score += 100
        elif is_reality:
            score += 80
        # TLS configs
        if is_tls:
            score += 60
        # Port 443 = never blocked
        if port == 443:
            score += 50
        elif port in LTE_SAFE_PORTS:
            score += 30
        # Known good SNIs
        good_snis = ["yandex", "vk.com", "google", "apple", "microsoft",
                     "cloudflare", "amazon", "x5.ru", "max.ru"]
        if any(s in sni.lower() for s in good_snis):
            score += 20
        # Fingerprint present
        if fp:
            score += 10
        # gRPC good for unstable connections
        if is_grpc:
            score += 15

        # Determine best network
        if is_reality and is_vision and port in PRIORITY_PORTS:
            best_for = "lte"
        elif is_reality and is_grpc:
            best_for = "3g"
        elif is_ws and is_tls:
            best_for = "wifi"
        elif is_reality:
            best_for = "lte"
        else:
            best_for = "all"

        # Create unique hash to deduplicate
        dedup_key = hashlib.md5(f"{uuid_part}@{host}:{port}".encode()).hexdigest()[:12]

        return {
            "raw": line.strip(),
            "uuid": uuid_part,
            "host": host,
            "port": port,
            "security": security,
            "transport": transport,
            "flow": flow,
            "sni": sni,
            "fp": fp,
            "pbk": pbk,
            "sid": sid,
            "name": name,
            "score": score,
            "best_for": best_for,
            "is_reality": is_reality,
            "is_vision": is_vision,
            "is_tls": is_tls,
            "is_ws": is_ws,
            "is_grpc": is_grpc,
            "dedup_key": dedup_key,
        }
    except Exception:
        return None


def parse_ss(line: str) -> dict | None:
    """Parse ss:// (Shadowsocks) URI."""
    line = line.strip()
    if not line.startswith("ss://"):
        return None
    try:
        if "#" in line:
            uri_part, fragment = line.rsplit("#", 1)
            name = unquote(fragment).strip()
        else:
            uri_part = line
            name = "SS"

        rest = uri_part[5:]  # remove ss://

        # Handle both formats: base64@host:port and method:pass@host:port
        if "@" in rest:
            encoded_part, server_part = rest.rsplit("@", 1)
            # Try base64 decode
            try:
                padding = (4 - len(encoded_part) % 4) % 4
                decoded = base64.urlsafe_b64decode(encoded_part + "=" * padding).decode()
                method, password = decoded.split(":", 1)
            except Exception:
                plain = unquote(encoded_part)
                if ":" not in plain:
                    return None
                method, password = plain.split(":", 1)
        else:
            # Fully base64 encoded
            try:
                padding = (4 - len(rest) % 4) % 4
                decoded = base64.urlsafe_b64decode(rest + "=" * padding).decode()
                if "@" in decoded:
                    cred_part, server_part = decoded.rsplit("@", 1)
                    method, password = cred_part.split(":", 1)
                else:
                    return None
            except Exception:
                return None

        # Parse host:port
        server_part = server_part.split("?")[0].split("/")[0]
        if ":" in server_part:
            host, port_str = server_part.rsplit(":", 1)
            host = host.strip("[]")
            port = int(port_str)
        else:
            return None

        dedup_key = hashlib.md5(f"ss-{method}:{password}@{host}:{port}".encode()).hexdigest()[:12]

        score = 40
        if port in LTE_SAFE_PORTS:
            score += 30
        if port == 443:
            score += 20

        return {
            "raw": line.strip(),
            "host": host,
            "port": port,
            "method": method,
            "name": name,
            "score": score,
            "best_for": "all",
            "is_reality": False,
            "is_vision": False,
            "is_tls": False,
            "is_ws": False,
            "is_grpc": False,
            "dedup_key": dedup_key,
            "type": "ss",
        }
    except Exception:
        return None


_fetch_lock = asyncio.Lock()
PROTO_PREFIXES = ("vless://", "ss://", "vmess://", "trojan://")


def decode_source(text: str) -> str:
    """Return plain-text config list; base64-decode the source if needed."""
    text = text.lstrip("\ufeff").strip()
    if text.startswith(PROTO_PREFIXES) or text.startswith("//"):
        return text
    try:
        compact = "".join(text.split())
        padding = (4 - len(compact) % 4) % 4
        decoded = base64.b64decode(compact + "=" * padding).decode("utf-8", errors="ignore").strip()
        if decoded.startswith(PROTO_PREFIXES):
            return decoded
    except Exception:
        pass
    return text


def _cache_fresh(now: float) -> bool:
    return _cache["last_update"] > 0 and (now - _cache["last_update"]) < CACHE_TTL


async def fetch_configs(force: bool = False) -> list[dict]:
    """Fetch configs from all sources, parse and deduplicate (cached, single-flight)."""
    if not force and _cache_fresh(time.time()):
        return _cache["configs"]
    async with _fetch_lock:
        if not force and _cache_fresh(time.time()):
            return _cache["configs"]
        return await _fetch_configs_uncached()


async def _fetch_configs_uncached() -> list[dict]:
    now = time.time()

    all_lines = []
    async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
        tasks = []
        for url in SOURCES:
            tasks.append(client.get(url))
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                continue
            if result.status_code == 200:
                all_lines.extend(decode_source(result.text).splitlines())

    # Parse all configs
    configs = []
    seen = set()
    for line in all_lines:
        line = line.strip()
        if not line or line.startswith("//") or line.startswith("#"):
            continue

        parsed = None
        if line.startswith("vless://"):
            parsed = parse_vless(line)
        elif line.startswith("ss://"):
            parsed = parse_ss(line)

        if parsed and parsed["dedup_key"] not in seen:
            seen.add(parsed["dedup_key"])
            configs.append(parsed)

    # Sort by score descending
    configs.sort(key=lambda x: x["score"], reverse=True)

    if not configs and _cache["configs"]:
        # All sources failed: keep serving the previous good list, retry soon.
        _cache["last_update"] = now - CACHE_TTL + 60
        return _cache["configs"]
    _cache["configs"] = configs
    _cache["last_update"] = now if configs else 0

    return configs


def build_subscription(configs: list[dict], network: str = "all",
                       max_configs: int = 50, port_filter: str = "") -> str:
    """Build Hiddify-compatible subscription text."""
    filtered = []
    port_set = set()
    if port_filter:
        port_set = {int(p.strip()) for p in port_filter.split(",") if p.strip().isdigit()}

    for c in configs:
        # Network filter
        if network == "lte":
            # For LTE: prefer REALITY, avoid plain WS without TLS
            if c.get("is_ws") and not c.get("is_tls"):
                continue
            if c["port"] not in LTE_SAFE_PORTS and not port_set:
                continue
        elif network == "3g":
            # For 3G: prefer gRPC and REALITY on safe ports
            if c["port"] not in LTE_SAFE_PORTS and not port_set:
                continue
        elif network == "wifi":
            # For WiFi: prefer WS/TLS, skip plain REALITY/TCP without TLS
            if not c.get("is_tls") and not c.get("is_ws"):
                continue

        # Port filter
        if port_set and c["port"] not in port_set:
            continue

        filtered.append(c)
        if len(filtered) >= max_configs:
            break

    # Build subscription text with headers
    now_ts = int(datetime.now(timezone.utc).timestamp())
    expire_ts = now_ts + 365 * 24 * 3600  # 1 year

    title = "🔑 Auto-Proxy"
    if network != "all":
        title += f" [{network.upper()}]"

    title_b64 = base64.b64encode(title.encode()).decode()

    lines = [
        f"//profile-title: base64:{title_b64}",
        "//profile-update-interval: 1",
        f"//subscription-userinfo: upload=0; download=0; total=10737418240000000; expire={expire_ts}",
        "//support-url: https://github.com/plojdjqpe-hash/AiMa",
        "",
    ]

    # Label configs based on requested network or best_for
    label_map = {
        "lte": "📡LTE",
        "3g": "📶3G",
        "wifi": "🌐WiFi",
        "all": "🔄Auto",
    }

    counter = 1
    for c in filtered:
        raw = c["raw"]
        if "#" in raw:
            raw_base = raw.rsplit("#", 1)[0]
        else:
            raw_base = raw

        if network != "all":
            prefix = label_map.get(network, "🔄Auto")
        else:
            prefix = label_map.get(c["best_for"], "🔄Auto")

        sni_tag = c.get("sni", "")[:20] if c.get("sni") else ""
        label = f"{prefix}-{counter} {sni_tag} :{c['port']}"
        lines.append(f"{raw_base}#{label}")
        counter += 1
        lines.append("")

    return "\n".join(lines)


@app.get("/")
async def root():
    return {
        "service": "Proxy Subscription for Hiddify",
        "endpoints": {
            "/sub": "All configs (auto-detect network)",
            "/sub?network=lte": "LTE optimized",
            "/sub?network=3g": "3G optimized",
            "/sub?network=wifi": "Wi-Fi optimized",
            "/sub?ports=443,8443,2053": "Filter by ports",
            "/sub?max=30": "Limit number of configs",
            "/sub/lte": "LTE shortcut",
            "/sub/3g": "3G shortcut",
            "/sub/wifi": "Wi-Fi shortcut",
            "/sub/best": "Top 20 best scoring configs",
            "/stats": "Stats about available configs",
            "/probe": "Real TCP latency probe of top configs",
        },
    }


@app.get("/sub")
async def subscription(
    network: str = Query("all", pattern="^(all|lte|3g|wifi)$", description="Network type: all, lte, 3g, wifi"),
    max: int = Query(50, ge=1, le=1000, description="Max configs to return"),
    ports: str = Query("", description="Comma-separated port filter"),
):
    configs = await fetch_configs()
    text = build_subscription(configs, network=network, max_configs=max, port_filter=ports)
    return PlainTextResponse(text, media_type="text/plain; charset=utf-8")


@app.get("/sub/lte")
async def sub_lte():
    configs = await fetch_configs()
    text = build_subscription(configs, network="lte", max_configs=40)
    return PlainTextResponse(text, media_type="text/plain; charset=utf-8")


@app.get("/sub/3g")
async def sub_3g():
    configs = await fetch_configs()
    text = build_subscription(configs, network="3g", max_configs=30)
    return PlainTextResponse(text, media_type="text/plain; charset=utf-8")


@app.get("/sub/wifi")
async def sub_wifi():
    configs = await fetch_configs()
    text = build_subscription(configs, network="wifi", max_configs=40)
    return PlainTextResponse(text, media_type="text/plain; charset=utf-8")


@app.get("/sub/best")
async def sub_best():
    """Top 20 highest scoring configs across all networks."""
    configs = await fetch_configs()
    text = build_subscription(configs, network="all", max_configs=20)
    return PlainTextResponse(text, media_type="text/plain; charset=utf-8")


@app.get("/stats")
async def stats():
    configs = await fetch_configs()
    total = len(configs)
    reality = sum(1 for c in configs if c.get("is_reality"))
    vision = sum(1 for c in configs if c.get("is_reality") and c.get("is_vision"))
    ws_tls = sum(1 for c in configs if c.get("is_ws") and c.get("is_tls"))
    grpc = sum(1 for c in configs if c.get("is_grpc"))
    ss = sum(1 for c in configs if c.get("type") == "ss")

    port_dist = {}
    for c in configs:
        p = c["port"]
        port_dist[p] = port_dist.get(p, 0) + 1
    top_ports = sorted(port_dist.items(), key=lambda x: x[1], reverse=True)[:10]

    lte = sum(1 for c in configs if c["best_for"] == "lte")
    wifi = sum(1 for c in configs if c["best_for"] == "wifi")
    g3 = sum(1 for c in configs if c["best_for"] == "3g")

    return {
        "total_configs": total,
        "by_type": {
            "reality": reality,
            "reality_vision": vision,
            "ws_tls": ws_tls,
            "grpc": grpc,
            "shadowsocks": ss,
        },
        "by_network": {
            "lte": lte,
            "wifi": wifi,
            "3g": g3,
        },
        "top_ports": dict(top_ports),
        "last_update": datetime.fromtimestamp(_cache["last_update"], tz=timezone.utc).isoformat() if _cache["last_update"] else None,
        "sources_count": len(SOURCES),
    }


@app.post("/refresh")
async def refresh_cache(x_refresh_token: str | None = Header(None)):
    """Force refresh config cache. Protected by REFRESH_TOKEN if it is set."""
    expected = os.getenv("REFRESH_TOKEN", "")
    if expected and x_refresh_token != expected:
        raise HTTPException(status_code=403, detail="invalid refresh token")
    configs = await fetch_configs(force=True)
    return {"status": "ok", "total_configs": len(configs)}


async def tcp_ping(host: str, port: int, timeout: float = 3.0) -> float | None:
    """Real TCP connect latency in ms, or None if unreachable."""
    start = time.perf_counter()
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except (OSError, asyncio.TimeoutError):
        return None
    elapsed = (time.perf_counter() - start) * 1000
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return round(elapsed, 1)


def config_kind(c: dict) -> str:
    if c.get("type") == "ss":
        return "SS"
    if c.get("is_reality"):
        return "REALITY"
    if c.get("is_grpc"):
        return "gRPC"
    if c.get("is_ws") and c.get("is_tls"):
        return "WS/TLS"
    return "VLESS"


@app.get("/probe")
async def probe(limit: int = Query(24, ge=1, le=100), network: str = Query("all", pattern="^(all|lte|3g|wifi)$")):
    """TCP-probe the top configs from the server side and return real latencies."""
    configs = await fetch_configs()
    if network != "all":
        configs = [c for c in configs if c["best_for"] == network]
    sample = configs[:limit]
    latencies = await asyncio.gather(*(tcp_ping(c["host"], c["port"]) for c in sample))
    results = [
        {
            "host": c["host"],
            "port": c["port"],
            "sni": c.get("sni", ""),
            "kind": config_kind(c),
            "name": c.get("name", ""),
            "latency_ms": lat,
            "online": lat is not None,
        }
        for c, lat in zip(sample, latencies, strict=True)
    ]
    online = [r for r in results if r["online"]]
    return {
        "tested": len(results),
        "online": len(online),
        "offline": len(results) - len(online),
        "avg_latency_ms": round(sum(r["latency_ms"] for r in online) / len(online), 1) if online else None,
        "port_443_reachable": any(r["port"] == 443 for r in online),
        "results": results,
    }


# Serve static webapp files
_webapp_dir = pathlib.Path(__file__).parent / "webapp"
if _webapp_dir.exists():
    app.mount("/app", StaticFiles(directory=str(_webapp_dir), html=True), name="webapp")
