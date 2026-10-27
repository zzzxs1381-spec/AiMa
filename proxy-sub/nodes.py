"""Parsers for the less common share-link schemes: vmess, trojan, hysteria2, tuic.

Every parser returns the same normalised dict shape that ``main.parse_vless``
produces, so scoring, filtering, health checks and format renderers can treat
all protocols uniformly.  ``params`` always carries the raw query parameters.
"""

from __future__ import annotations

import base64
import hashlib
import json
from urllib.parse import parse_qsl, unquote

LTE_SAFE_PORTS = {443, 2053, 2083, 2087, 2096, 8443, 8080, 80}
UDP_TYPES = {"hysteria2", "tuic"}
SCHEMES = {
    "vless": "vless",
    "vmess": "vmess",
    "trojan": "trojan",
    "ss": "ss",
    "hysteria2": "hysteria2",
    "hy2": "hysteria2",
    "tuic": "tuic",
}


def b64decode_any(text: str) -> str:
    text = text.strip()
    pad = "=" * ((4 - len(text) % 4) % 4)
    for fn in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return fn(text + pad).decode("utf-8")
        except Exception:
            continue
    raise ValueError("not base64")


def _hostport(text: str) -> tuple[str, str]:
    """Split ``host:port`` (IPv6 aware); the port may stay a string like ``443,5000-6000``."""
    text = text.split("/")[0]
    if text.startswith("["):
        end = text.index("]")
        return text[1:end], text[end + 2:]
    host, _, port = text.rpartition(":")
    return host, port


def _split(line: str, scheme_len: int):
    body, _, frag = line[scheme_len:].partition("#")
    name = unquote(frag).strip()
    main_part, _, query = body.partition("?")
    params = dict(parse_qsl(query, keep_blank_values=True))
    return main_part, params, name


def _dedup(*parts: object) -> str:
    return hashlib.md5("|".join(str(p) for p in parts).encode()).hexdigest()[:12]


def _score(port: int, base: int, tls: bool = False, bonus: int = 0) -> int:
    score = base + bonus
    if tls:
        score += 20
    if port == 443:
        score += 50
    elif port in LTE_SAFE_PORTS:
        score += 30
    return score


def parse_vmess(line: str) -> dict | None:
    line = line.strip()
    if not line.startswith("vmess://"):
        return None
    try:
        body, _, frag = line[8:].partition("#")
        if "@" in body:  # URL style: vmess://uuid@host:port?type=ws...
            user, rest = body.rsplit("@", 1)
            main_part, _, query = rest.partition("?")
            host, port_s = _hostport(main_part)
            params = dict(parse_qsl(query, keep_blank_values=True))
            uuid = user
            net = params.get("type", "tcp")
            tls = params.get("security", "") == "tls"
            sni = params.get("sni", "")
            path = params.get("path", "")
            host_header = params.get("host", "")
            name = unquote(frag).strip()
            aid = int(params.get("aid", 0) or 0)
            cipher = params.get("scy", "auto")
            alpn = params.get("alpn", "")
            fp = params.get("fp", "")
        else:
            j = json.loads(b64decode_any(body))
            host, port_s = str(j["add"]), str(j["port"])
            uuid = str(j["id"])
            net = j.get("net") or "tcp"
            tls = (j.get("tls") or "") == "tls"
            sni = j.get("sni") or ""
            path = j.get("path") or ""
            host_header = j.get("host") or ""
            name = str(j.get("ps") or "").strip()
            aid = int(j.get("aid") or 0)
            cipher = j.get("scy") or "auto"
            alpn = j.get("alpn") or ""
            fp = j.get("fp") or ""
        port = int(port_s)
        if not host or not uuid:
            return None
        if not sni and tls:
            sni = host_header or ""
        params = {"path": path, "host": host_header, "alpn": alpn, "fp": fp, "aid": str(aid), "scy": cipher}
        is_ws = net == "ws"
        is_grpc = net == "grpc"
        score = _score(port, 30, tls, 15 if (is_ws and tls) else 0)
        return {
            "raw": line, "type": "vmess", "uuid": uuid, "host": host, "port": port,
            "security": "tls" if tls else "none", "transport": net, "flow": "", "sni": sni, "fp": fp,
            "pbk": "", "sid": "", "name": name, "score": score,
            "best_for": "wifi" if (is_ws and tls) else "all",
            "is_reality": False, "is_vision": False, "is_tls": tls, "is_ws": is_ws, "is_grpc": is_grpc,
            "dedup_key": _dedup("vmess", uuid, host, port), "params": params,
        }
    except Exception:
        return None


def parse_trojan(line: str) -> dict | None:
    line = line.strip()
    if not line.startswith("trojan://"):
        return None
    try:
        main_part, params, name = _split(line, 9)
        if "@" not in main_part:
            return None
        password, server = main_part.rsplit("@", 1)
        host, port_s = _hostport(server)
        port = int(port_s)
        password = unquote(password)
        net = params.get("type", "tcp")
        sec = params.get("security", "tls")
        tls = sec in ("tls", "reality")
        sni = params.get("sni") or params.get("peer", "")
        is_ws = net == "ws"
        is_grpc = net == "grpc"
        score = _score(port, 45, True, 10 if (is_ws or is_grpc) else 0)
        return {
            "raw": line, "type": "trojan", "password": password, "host": host, "port": port,
            "security": sec, "transport": net, "flow": "", "sni": sni, "fp": params.get("fp", ""),
            "pbk": params.get("pbk", ""), "sid": params.get("sid", ""), "name": name, "score": score,
            "best_for": "wifi" if is_ws else "all",
            "is_reality": sec == "reality", "is_vision": False, "is_tls": tls, "is_ws": is_ws, "is_grpc": is_grpc,
            "dedup_key": _dedup("trojan", password, host, port), "params": params,
        }
    except Exception:
        return None


def parse_hysteria2(line: str) -> dict | None:
    line = line.strip()
    scheme = "hysteria2://" if line.startswith("hysteria2://") else "hy2://" if line.startswith("hy2://") else ""
    if not scheme:
        return None
    try:
        main_part, params, name = _split(line, len(scheme))
        if "@" not in main_part:
            return None
        password, server = main_part.rsplit("@", 1)
        host, port_s = _hostport(server)
        port_first = port_s.replace("-", ",").split(",")[0]
        port = int(port_first)
        password = unquote(password)
        sni = params.get("sni", "")
        return {
            "raw": line, "type": "hysteria2", "password": password, "host": host, "port": port,
            "ports": port_s if ("," in port_s or "-" in port_s) else "",
            "security": "tls", "transport": "udp", "flow": "", "sni": sni, "fp": "", "pbk": "", "sid": "",
            "name": name, "score": _score(port, 50, True),
            "best_for": "all", "is_reality": False, "is_vision": False, "is_tls": True,
            "is_ws": False, "is_grpc": False,
            "dedup_key": _dedup("hy2", password, host, port), "params": params,
        }
    except Exception:
        return None


def parse_tuic(line: str) -> dict | None:
    line = line.strip()
    if not line.startswith("tuic://"):
        return None
    try:
        main_part, params, name = _split(line, 7)
        if "@" not in main_part:
            return None
        user, server = main_part.rsplit("@", 1)
        uuid, _, password = unquote(user).partition(":")
        host, port_s = _hostport(server)
        port = int(port_s)
        return {
            "raw": line, "type": "tuic", "uuid": uuid, "password": password, "host": host, "port": port,
            "security": "tls", "transport": "udp", "flow": "", "sni": params.get("sni", ""), "fp": "",
            "pbk": "", "sid": "", "name": name, "score": _score(port, 45, True),
            "best_for": "all", "is_reality": False, "is_vision": False, "is_tls": True,
            "is_ws": False, "is_grpc": False,
            "dedup_key": _dedup("tuic", uuid, password, host, port), "params": params,
        }
    except Exception:
        return None


def scheme_of(line: str) -> str | None:
    head, sep, _ = line.partition("://")
    return SCHEMES.get(head) if sep else None
