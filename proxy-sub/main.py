"""
Proxy Subscription Service for Hiddify
Auto-fetches, filters, and serves optimized VLESS/SS configs
Supports LTE/3G/Wi-Fi with auto-switching
"""

import asyncio
import base64
import contextlib
import hashlib
import math
import os
import pathlib
import time
from datetime import UTC, datetime
from urllib.parse import parse_qsl, unquote

import formats
import geo
import health
import httpx
from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from nodes import (
    UDP_TYPES,
    parse_hysteria2,
    parse_trojan,
    parse_tuic,
    parse_vmess,
    scheme_of,
)

REFRESH_INTERVAL = int(os.getenv("REFRESH_INTERVAL", "600"))
HEALTH_CANDIDATES = int(os.getenv("HEALTH_CANDIDATES", "500"))
COLD_START_WAIT = float(os.getenv("COLD_START_WAIT", "15"))
SS_AEAD = {"aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "chacha20-poly1305",
           "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
           "2022-blake3-chacha20-poly1305", "none"}
MAX_PER_HOST = int(os.getenv("MAX_PER_HOST", "2"))
UDP_SLOTS_PERCENT = int(os.getenv("UDP_SLOTS_PERCENT", "10"))
PROFILE_TITLE = os.getenv("PROFILE_TITLE", "XFreedom")
SUPPORT_URL = os.getenv("SUPPORT_URL", "https://xfreedom.ink")
PROFILE_INTERVAL = int(os.getenv("PROFILE_UPDATE_INTERVAL", "1"))
SUB_TOTAL_BYTES = int(os.getenv("SUB_TOTAL_BYTES", "10737418240000000"))
SUB_EXPIRE_DAYS = int(os.getenv("SUB_EXPIRE_DAYS", "365"))

_bg_tasks: set[asyncio.Task] = set()


@contextlib.asynccontextmanager
async def lifespan(_app: FastAPI):
    task = None
    if os.getenv("DISABLE_BACKGROUND", "") != "1":
        task = asyncio.create_task(_refresh_loop())
    yield
    if task:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


app = FastAPI(title="Proxy Subscription Service", lifespan=lifespan)

# === CONFIG SOURCES ===
SOURCES = [
    "https://raw.githubusercontent.com/4n0nymou3/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs.txt",
    "https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/refs/heads/main/Reality",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.txt",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
] + [u for u in os.getenv("EXTRA_SOURCES", "").split(",") if u.strip()]

# Cache
_cache: dict = {"configs": [], "last_update": 0, "raw_text": "", "sources": []}
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
            "type": "vless",
            "params": params,
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
        plugin = ""
        if "?" in server_part:
            query = dict(parse_qsl(server_part.split("?", 1)[1]))
            plugin = query.get("plugin", "")
        server_part = server_part.split("?")[0].split("/")[0]
        if ":" in server_part:
            host, port_str = server_part.rsplit(":", 1)
            host = host.strip("[]")
            port = int(port_str)
        else:
            return None

        if method.lower() not in SS_AEAD:
            return None  # legacy stream ciphers (cfb/rc4/...) are insecure and rejected by modern cores

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
            "password": password,
            "plugin": plugin,
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
_pipeline_lock = asyncio.Lock()
PROTO_PREFIXES = ("vless://", "ss://", "vmess://", "trojan://", "hysteria2://", "hy2://", "tuic://")


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


def parse_line(line: str) -> dict | None:
    """Parse one share link of any supported protocol into the common node dict."""
    scheme = scheme_of(line)
    if scheme == "vless":
        return parse_vless(line)
    if scheme == "ss":
        return parse_ss(line)
    if scheme == "vmess":
        return parse_vmess(line)
    if scheme == "trojan":
        return parse_trojan(line)
    if scheme == "hysteria2":
        return parse_hysteria2(line)
    if scheme == "tuic":
        return parse_tuic(line)
    return None


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


def dedupe(configs: list[dict]) -> list[dict]:
    """Drop exact duplicates and extra credentials on the same host:port (best score wins)."""
    configs = sorted(configs, key=lambda x: x["score"], reverse=True)
    seen_keys: set[str] = set()
    seen_endpoints: set[tuple] = set()
    out = []
    for c in configs:
        endpoint = (c.get("type", "vless"), c["host"].lower(), c["port"])
        if c["dedup_key"] in seen_keys or endpoint in seen_endpoints:
            continue
        seen_keys.add(c["dedup_key"])
        seen_endpoints.add(endpoint)
        out.append(c)
    return out


async def _fetch_configs_uncached() -> list[dict]:
    now = time.time()

    all_lines = []
    report = []
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        results = await asyncio.gather(*(client.get(url) for url in SOURCES), return_exceptions=True)

        for url, result in zip(SOURCES, results, strict=True):
            if isinstance(result, Exception):
                report.append({"url": url, "ok": False, "status": None, "lines": 0})
                continue
            lines = decode_source(result.text).splitlines() if result.status_code == 200 else []
            report.append({"url": url, "ok": result.status_code == 200 and bool(lines),
                           "status": result.status_code, "lines": len(lines)})
            all_lines.extend(lines)

    parsed_all = []
    for line in all_lines:
        line = line.strip()
        if not line or line.startswith("//") or line.startswith("#"):
            continue
        parsed = parse_line(line)
        if parsed:
            parsed_all.append(parsed)
    configs = dedupe(parsed_all)

    if not configs and _cache["configs"]:
        # All sources failed: keep serving the previous good list, retry soon.
        _cache["last_update"] = now - CACHE_TTL + 60
        return _cache["configs"]
    _cache["configs"] = configs
    _cache["sources"] = report
    _cache["last_update"] = now if configs else 0

    return configs


# ---------------------------------------------------------------- selection
def _network_ok(c: dict, network: str, port_set: set[int]) -> bool:
    if network == "lte":
        if c.get("is_ws") and not c.get("is_tls"):
            return False
        if c["port"] not in LTE_SAFE_PORTS and not port_set:
            return False
    elif network == "3g":
        if c["port"] not in LTE_SAFE_PORTS and not port_set:
            return False
    elif network == "wifi":
        if not c.get("is_tls") and not c.get("is_ws"):
            return False
    return not port_set or c["port"] in port_set


def candidate_nodes(configs: list[dict], limit: int = HEALTH_CANDIDATES) -> list[dict]:
    """Top nodes overall plus the best of every protocol, so rarer protocols still get probed."""
    chosen = {c["dedup_key"]: c for c in configs[:limit]}
    by_type: dict[str, int] = {}
    for c in configs:
        t = c.get("type", "vless")
        if by_type.get(t, 0) < 60:
            by_type[t] = by_type.get(t, 0) + 1
            chosen.setdefault(c["dedup_key"], c)
    return list(chosen.values())


def select_nodes(configs: list[dict], network: str = "all", max_configs: int = 50, port_filter: str = "",
                 protocols: set[str] | None = None, countries: set[str] | None = None,
                 only_alive: bool = True) -> list[dict]:
    """Filter by network/protocol/country, drop dead nodes, rank by score and measured latency, keep variety."""
    port_set = {int(p) for p in port_filter.split(",") if p.strip().isdigit()} if port_filter else set()
    pool = [c for c in configs if _network_ok(c, network, port_set)]
    if protocols:
        pool = [c for c in pool if c.get("type", "vless") in protocols]
    if countries:
        pool = [c for c in pool if (c.get("country") or "").upper() in countries]

    ranked = []
    have_health = any(health.get(c, max_age=health.HEALTH_TTL * 2) for c in pool)
    for c in pool:
        h = health.get(c, max_age=health.HEALTH_TTL * 2)
        if only_alive and have_health:
            if h is None or h["alive"] is False:
                continue
        if h:
            c["cert_ok"] = h.get("cert_ok")
        ms = h["ms"] if h and h["alive"] else None
        alive_bonus = 0 if h is None else (1000 if h["alive"] else -1000 if h["alive"] is False else 0)
        ranked.append((c["score"] + alive_bonus - (ms or 0) / 20, c))
    ranked.sort(key=lambda t: t[0], reverse=True)

    per_host: dict[str, int] = {}
    per_country: dict[str, int] = {}
    country_cap = max(3, math.ceil(max_configs * 0.4))
    out: list[dict] = []

    def take(items: list[dict], limit: int) -> None:
        taken = 0
        for c in items:
            if taken >= limit:
                return
            host = c["host"].lower()
            cc = c.get("country") or ""
            if per_host.get(host, 0) >= MAX_PER_HOST:
                continue
            if cc and not countries and per_country.get(cc, 0) >= country_cap:
                continue
            per_host[host] = per_host.get(host, 0) + 1
            if cc:
                per_country[cc] = per_country.get(cc, 0) + 1
            out.append(c)
            taken += 1

    tcp_tls = [c for _, c in ranked if c.get("type") not in UDP_TYPES]
    udp_nodes = [c for _, c in ranked if c.get("type") in UDP_TYPES]
    # UDP protocols cannot be probed from here: they only get a small reserved share (all slots if asked for explicitly).
    udp_only = bool(protocols) and protocols <= UDP_TYPES
    udp_slots = max_configs if udp_only else max(2, max_configs * UDP_SLOTS_PERCENT // 100)
    udp_slots = min(udp_slots, len(udp_nodes), max_configs)
    take(tcp_tls, max_configs - udp_slots)
    take(udp_nodes, min(udp_slots, max_configs - len(out)))
    return out[:max_configs]


# ---------------------------------------------------------------- health pipeline
def _spawn(coro) -> asyncio.Task:
    task = asyncio.create_task(coro)
    _bg_tasks.add(task)
    task.add_done_callback(_bg_tasks.discard)
    return task


async def _probe_and_geo(cands: list[dict]) -> None:
    stale = [c for c in cands if health.needs_check(c)]
    await asyncio.gather(geo.annotate_countries(cands), health.check_nodes(stale))


async def refresh_pipeline(force: bool = False) -> dict:
    """Fetch sources, geolocate and health-check the best candidates (single-flight)."""
    async with _pipeline_lock:
        configs = await fetch_configs(force=force)
        await _probe_and_geo(candidate_nodes(configs))
        return health.summary(configs)


async def _refresh_loop() -> None:
    while True:
        try:
            await refresh_pipeline()
        except Exception as exc:  # keep the loop alive whatever a single round throws
            print(f"refresh round failed: {exc!r}")
        await asyncio.sleep(REFRESH_INTERVAL)


async def ensure_health(configs: list[dict]) -> None:
    """Make sure the candidate nodes have recent health data.

    Cold start: wait (bounded) so the very first subscription already excludes dead nodes.
    Warm: serve what we have and refresh in the background.
    """
    cands = candidate_nodes(configs)
    if not any(health.get(c) for c in cands):
        task = _spawn(_probe_and_geo(cands))
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(asyncio.shield(task), COLD_START_WAIT)
    elif any(health.needs_check(c) for c in cands) and not _pipeline_lock.locked():
        _spawn(_probe_and_geo(cands))


# ---------------------------------------------------------------- legacy text builder
def build_subscription(configs: list[dict], network: str = "all",
                       max_configs: int = 50, port_filter: str = "") -> str:
    """Plain-text list (with // meta comment lines) of the selected nodes."""
    selected = select_nodes(configs, network=network, max_configs=max_configs, port_filter=port_filter)
    title = PROFILE_TITLE if network == "all" else f"{PROFILE_TITLE} [{network.upper()}]"
    expire = int(time.time()) + SUB_EXPIRE_DAYS * 86400
    meta = {
        "profile-title": formats.b64_header(title),
        "profile-update-interval": str(PROFILE_INTERVAL),
        "subscription-userinfo": f"upload=0; download=0; total={SUB_TOTAL_BYTES}; expire={expire}",
        "support-url": SUPPORT_URL,
    }
    return formats.render_uri(selected, meta)[0]


# ---------------------------------------------------------------- endpoints
def _csv(value: str, upper: bool = False) -> set[str]:
    items = {x.strip() for x in value.split(",") if x.strip()}
    return {x.upper() for x in items} if upper else {x.lower() for x in items}


async def serve_subscription(network: str, max_configs: int, ports: str, fmt: str | None, user_agent: str | None,
                             protocol: str = "", country: str = "", alive: bool = True) -> Response:
    configs = await fetch_configs()
    await ensure_health(configs)
    fmt_name = formats.detect_format(user_agent, fmt)
    selected = select_nodes(configs, network=network, max_configs=max_configs, port_filter=ports,
                            protocols=_csv(protocol) or None, countries=_csv(country, upper=True) or None,
                            only_alive=alive)
    if not selected:
        raise HTTPException(status_code=503, detail="no live nodes yet, retry shortly", headers={"Retry-After": "30"})
    await geo.annotate_countries(selected)

    title = PROFILE_TITLE if network == "all" else f"{PROFILE_TITLE} {network.upper()}"
    now = int(time.time())
    expire = now + SUB_EXPIRE_DAYS * 86400
    summ = health.summary(selected)
    announce = os.getenv("ANNOUNCE") or (
        f"✅ Проверено живых узлов: {summ['alive']} из {len(selected)}. "
        f"Обновлено {datetime.now(UTC).strftime('%H:%M')} UTC. Поддержка: {SUPPORT_URL}"
    )
    hdrs = formats.build_headers(
        fmt_name, title=title, interval=PROFILE_INTERVAL, support_url=SUPPORT_URL,
        web_page=os.getenv("PUBLIC_URL", SUPPORT_URL), announce=announce, total=SUB_TOTAL_BYTES, expire=expire,
        refill=int(os.getenv("SUB_REFILL_TS", "0")) or None, live=summ["alive"], checked=len(selected),
        filename=formats.safe_filename(title, fmt_name),
    )
    body_meta = {k: hdrs[k] for k in ("profile-title", "profile-update-interval", "subscription-userinfo", "support-url")}
    body, count = formats.render(fmt_name, selected, title=PROFILE_TITLE, body_headers=body_meta)
    if count == 0:
        raise HTTPException(status_code=503, detail=f"none of the nodes can be expressed as {fmt_name}")
    hdrs["x-format"] = fmt_name
    hdrs["x-nodes"] = str(count)
    return Response(content=body, media_type=formats.CONTENT_TYPES[fmt_name], headers=hdrs)


@app.get("/")
async def root():
    return {
        "service": "Proxy Subscription for Hiddify, Clash, sing-box, Xray",
        "formats": list(formats.FORMATS),
        "endpoints": {
            "/sub": "Live-checked configs; format is auto-detected from the client User-Agent",
            "/sub?format=clash|singbox|xray|base64|uri": "Force a format",
            "/sub?network=lte|3g|wifi": "Network profile",
            "/sub?protocol=vless,trojan,hysteria2": "Filter by protocol",
            "/sub?country=DE,NL": "Filter by country",
            "/sub?alive=0": "Do not drop nodes that failed the health check",
            "/sub?ports=443,8443": "Filter by ports",
            "/sub?max=30": "Limit number of configs",
            "/sub/lte": "LTE shortcut",
            "/sub/3g": "3G shortcut",
            "/sub/wifi": "Wi-Fi shortcut",
            "/sub/best": "Top 20 best configs",
            "/stats": "Pool, protocol, country and health statistics",
            "/health": "Liveness summary of the node pool",
            "/probe": "Real TLS/TCP probe of the top configs",
        },
    }


@app.api_route("/sub", methods=["GET", "HEAD"])
async def subscription(
    network: str = Query("all", pattern="^(all|lte|3g|wifi)$", description="Network type: all, lte, 3g, wifi"),
    max: int = Query(50, ge=1, le=1000, description="Max configs to return"),
    ports: str = Query("", description="Comma-separated port filter"),
    format: str | None = Query(None, pattern="^(base64|uri|clash|singbox|xray)$", description="Output format"),
    protocol: str = Query("", description="Comma-separated protocols"),
    country: str = Query("", description="Comma-separated ISO country codes"),
    alive: bool = Query(True, description="Drop nodes that failed the health check"),
    user_agent: str | None = Header(None),
):
    return await serve_subscription(network, max, ports, format, user_agent, protocol, country, alive)


@app.api_route("/sub/lte", methods=["GET", "HEAD"])
async def sub_lte(format: str | None = Query(None, pattern="^(base64|uri|clash|singbox|xray)$"),
                  user_agent: str | None = Header(None)):
    return await serve_subscription("lte", 40, "", format, user_agent)


@app.api_route("/sub/3g", methods=["GET", "HEAD"])
async def sub_3g(format: str | None = Query(None, pattern="^(base64|uri|clash|singbox|xray)$"),
                 user_agent: str | None = Header(None)):
    return await serve_subscription("3g", 30, "", format, user_agent)


@app.api_route("/sub/wifi", methods=["GET", "HEAD"])
async def sub_wifi(format: str | None = Query(None, pattern="^(base64|uri|clash|singbox|xray)$"),
                   user_agent: str | None = Header(None)):
    return await serve_subscription("wifi", 40, "", format, user_agent)


@app.api_route("/sub/best", methods=["GET", "HEAD"])
async def sub_best(format: str | None = Query(None, pattern="^(base64|uri|clash|singbox|xray)$"),
                   user_agent: str | None = Header(None)):
    """Top 20 highest scoring live configs across all networks."""
    return await serve_subscription("all", 20, "", format, user_agent)


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

    by_protocol: dict[str, int] = {}
    by_country: dict[str, int] = {}
    for c in configs:
        by_protocol[c.get("type", "vless")] = by_protocol.get(c.get("type", "vless"), 0) + 1
        if c.get("country"):
            by_country[c["country"]] = by_country.get(c["country"], 0) + 1

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
        "by_protocol": by_protocol,
        "by_country": dict(sorted(by_country.items(), key=lambda x: x[1], reverse=True)),
        "by_network": {
            "lte": lte,
            "wifi": wifi,
            "3g": g3,
        },
        "health": health.summary(configs),
        "top_ports": dict(top_ports),
        "last_update": datetime.fromtimestamp(_cache["last_update"], tz=UTC).isoformat() if _cache["last_update"] else None,
        "sources_count": len(SOURCES),
        "sources_ok": sum(1 for s in _cache["sources"] if s["ok"]),
        "formats": list(formats.FORMATS),
    }


@app.get("/health")
async def health_endpoint():
    configs = await fetch_configs()
    return {"status": "ok", "pool": health.summary(configs), "refresh_interval_s": REFRESH_INTERVAL,
            "health_ttl_s": health.HEALTH_TTL}


@app.post("/refresh")
async def refresh_cache(x_refresh_token: str | None = Header(None)):
    """Force refresh config cache. Protected by REFRESH_TOKEN if it is set."""
    expected = os.getenv("REFRESH_TOKEN", "")
    if expected and x_refresh_token != expected:
        raise HTTPException(status_code=403, detail="invalid refresh token")
    configs = await fetch_configs(force=True)
    if os.getenv("DISABLE_BACKGROUND", "") != "1":
        _spawn(_probe_and_geo(candidate_nodes(configs)))
    return {"status": "ok", "total_configs": len(configs)}


async def tcp_ping(host: str, port: int, timeout: float = 3.0) -> float | None:
    """Real TCP connect latency in ms, or None if unreachable."""
    return await health.tcp_connect(host, port, timeout)


def config_kind(c: dict) -> str:
    kind = formats.kind_label(c)
    return {"Reality-Vision": "REALITY", "Reality": "REALITY", "WS-TLS": "WS/TLS", "VMess-WS": "VMess"}.get(kind, kind)


@app.get("/probe")
async def probe(limit: int = Query(24, ge=1, le=100), network: str = Query("all", pattern="^(all|lte|3g|wifi)$")):
    """Probe the top configs from the server side (TLS handshake for TLS nodes) and return real latencies."""
    configs = await fetch_configs()
    if network != "all":
        configs = [c for c in configs if c["best_for"] == network]
    sample = configs[:limit]
    checks = await asyncio.gather(*(health.check_node(c) for c in sample))
    for c, h in zip(sample, checks, strict=True):
        health._health[c["dedup_key"]] = h
    results = [
        {
            "host": c["host"],
            "port": c["port"],
            "sni": c.get("sni", ""),
            "kind": config_kind(c),
            "name": c.get("name", ""),
            "latency_ms": h["ms"],
            "online": bool(h["alive"]),
            "method": h["method"],
        }
        for c, h in zip(sample, checks, strict=True)
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
