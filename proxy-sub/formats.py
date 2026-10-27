"""Subscription renderers: URI list, base64, Clash/mihomo, sing-box, Xray JSON.

Also holds the shared routing rules (Russian services go direct), client
detection by User-Agent and the HTTP headers of a subscription response.
"""

from __future__ import annotations

import base64
import json
import re
import time
from urllib.parse import quote

from geo import country_name, flag

# ---------------------------------------------------------------- routing
RU_DOMAIN_SUFFIXES = [
    "ru", "su", "xn--p1ai", "yandex.net", "yandex.com", "yandex.by", "yandex.kz", "ya.ru",
    "vk.com", "vk.me", "vk-cdn.net", "userapi.com", "mycdn.me", "mail.ru", "ok.ru", "max.ru",
    "2gis.com", "kinopoisk.ru", "sberbank.com", "tinkoff.ru", "gosuslugi.ru", "local",
]
CHECK_URL = "https://www.gstatic.com/generate_204"
DNS_REMOTE = "https://1.1.1.1/dns-query"
DNS_DOMESTIC = "77.88.8.8"
GEOIP_RU_SRS = "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ru.srs"

FORMATS = ("base64", "uri", "clash", "singbox", "xray")
CONTENT_TYPES = {
    "base64": "text/plain; charset=utf-8",
    "uri": "text/plain; charset=utf-8",
    "clash": "text/yaml; charset=utf-8",
    "singbox": "application/json; charset=utf-8",
    "xray": "application/json; charset=utf-8",
}
EXTENSIONS = {"base64": "txt", "uri": "txt", "clash": "yaml", "singbox": "json", "xray": "json"}

_CLASH_UA = ("clash", "mihomo", "stash", "flclash", "verge", "cmfa", "koala")
_SINGBOX_UA = ("sing-box", "singbox", "sfa/", "sfi/", "sfm/", "sft/", "karing")
_XRAY_UA = ("xray-json", "v2rayn-json")
_BROWSER_UA = ("mozilla", "chrome", "safari", "firefox", "edge")


def detect_format(user_agent: str | None, explicit: str | None = None) -> str:
    """Pick the output format: explicit ``?format=`` wins, else sniff the client UA."""
    if explicit and explicit.lower() in FORMATS:
        return explicit.lower()
    ua = (user_agent or "").lower()
    if any(k in ua for k in _XRAY_UA):
        return "xray"
    if any(k in ua for k in _CLASH_UA):
        return "clash"
    if any(k in ua for k in _SINGBOX_UA):
        return "singbox"
    if any(k in ua for k in _BROWSER_UA) and not any(k in ua for k in ("hiddify", "v2ray", "happ", "streisand")):
        return "uri"  # a person in a browser: readable list instead of base64
    return "base64"


# ---------------------------------------------------------------- naming
def kind_label(c: dict) -> str:
    t = c.get("type", "vless")
    if t == "ss":
        return "SS"
    if t == "vmess":
        return "VMess-WS" if c.get("is_ws") else "VMess"
    if t == "trojan":
        return "Trojan"
    if t == "hysteria2":
        return "Hysteria2"
    if t == "tuic":
        return "TUIC"
    if c.get("is_reality"):
        return "Reality-Vision" if c.get("is_vision") else "Reality"
    if c.get("transport") == "xhttp":
        return "XHTTP"
    if c.get("is_grpc"):
        return "gRPC"
    if c.get("is_ws") and c.get("is_tls"):
        return "WS-TLS"
    return "VLESS"


def display_names(nodes: list[dict]) -> list[str]:
    """Unique, human names: ``🇩🇪 Германия · Reality-Vision #1``."""
    counters: dict[str, int] = {}
    names = []
    for c in nodes:
        base = f"{flag(c.get('country'))} {country_name(c.get('country'))} · {kind_label(c)}"
        counters[base] = counters.get(base, 0) + 1
        names.append(f"{base} #{counters[base]}")
    return names


# ---------------------------------------------------------------- helpers
def _params(c: dict) -> dict:
    return c.get("params") or {}


def _net(c: dict) -> str:
    net = c.get("transport") or _params(c).get("type", "tcp")
    return "tcp" if net in ("raw", "") else net


def _alpn(c: dict) -> list[str]:
    a = _params(c).get("alpn", "")
    return [x for x in a.split(",") if x]


_FPS = {"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"}


def norm_fp(fp: str | None, clash: bool = False) -> str:
    """Only fingerprints every client understands; anything odd falls back to chrome."""
    fp = (fp or "").lower()
    if fp not in _FPS:
        return "chrome"
    return "random" if clash and fp == "randomized" else fp


def _y(obj) -> str:
    """JSON is valid YAML: one-line flow style keeps every string correctly quoted."""
    return json.dumps(obj, ensure_ascii=False)


def with_name(uri: str, name: str) -> str:
    base = uri.rsplit("#", 1)[0] if "#" in uri else uri
    if base.startswith("vmess://") and "@" not in base:
        try:
            raw = base[8:]
            j = json.loads(base64.b64decode(raw + "=" * ((4 - len(raw) % 4) % 4)))
            j["ps"] = name
            return "vmess://" + base64.b64encode(json.dumps(j, ensure_ascii=False).encode()).decode()
        except Exception:
            return base
    return f"{base}#{quote(name)}"


# ---------------------------------------------------------------- clash
def clash_proxy(c: dict, name: str) -> dict | None:
    t = c.get("type", "vless")
    p = _params(c)
    net = _net(c)
    if t == "vless":
        if net not in ("tcp", "ws", "grpc"):
            return None
        d = {"name": name, "type": "vless", "server": c["host"], "port": c["port"], "uuid": c["uuid"],
             "udp": True, "network": net, "packet-encoding": "xudp"}
        if c.get("flow"):
            d["flow"] = c["flow"]
        if c.get("is_reality"):
            if not c.get("pbk"):
                return None
            d.update({"tls": True, "servername": c.get("sni", ""), "client-fingerprint": norm_fp(c.get("fp"), True),
                      "reality-opts": {"public-key": c["pbk"], "short-id": c.get("sid", "")}})
        elif c.get("is_tls"):
            d.update({"tls": True, "servername": c.get("sni") or c["host"], "skip-cert-verify": True})
            if c.get("fp"):
                d["client-fingerprint"] = norm_fp(c["fp"], True)
            if _alpn(c):
                d["alpn"] = _alpn(c)
        elif c.get("security") not in ("none", ""):
            return None
        _clash_transport(d, net, p)
        return d
    if t == "vmess":
        if net not in ("tcp", "ws", "grpc"):
            return None
        d = {"name": name, "type": "vmess", "server": c["host"], "port": c["port"], "uuid": c["uuid"],
             "alterId": int(p.get("aid", 0) or 0), "cipher": p.get("scy") or "auto", "udp": True, "network": net}
        if c.get("is_tls"):
            d.update({"tls": True, "servername": c.get("sni") or p.get("host") or c["host"], "skip-cert-verify": True})
        _clash_transport(d, net, p)
        return d
    if t == "trojan":
        if net not in ("tcp", "ws", "grpc") or c.get("is_reality"):
            return None
        d = {"name": name, "type": "trojan", "server": c["host"], "port": c["port"], "password": c["password"],
             "udp": True, "sni": c.get("sni") or c["host"], "skip-cert-verify": True, "network": net}
        _clash_transport(d, net, p)
        return d
    if t == "ss":
        if c.get("plugin"):
            return None
        return {"name": name, "type": "ss", "server": c["host"], "port": c["port"], "cipher": c["method"],
                "password": c["password"], "udp": True}
    if t == "hysteria2":
        d = {"name": name, "type": "hysteria2", "server": c["host"], "port": c["port"], "password": c["password"],
             "sni": c.get("sni") or c["host"], "skip-cert-verify": True}
        if p.get("obfs"):
            d.update({"obfs": p["obfs"], "obfs-password": p.get("obfs-password", "")})
        return d
    if t == "tuic":
        return {"name": name, "type": "tuic", "server": c["host"], "port": c["port"], "uuid": c["uuid"],
                "password": c.get("password", ""), "sni": c.get("sni") or c["host"], "skip-cert-verify": True,
                "alpn": _alpn(c) or ["h3"], "congestion-controller": p.get("congestion_control", "bbr"),
                "udp-relay-mode": p.get("udp_relay_mode", "native")}
    return None


def _clash_transport(d: dict, net: str, p: dict) -> None:
    if net == "ws":
        ws = {"path": p.get("path") or "/"}
        if p.get("host"):
            ws["headers"] = {"Host": p["host"]}
        d["ws-opts"] = ws
    elif net == "grpc":
        d["grpc-opts"] = {"grpc-service-name": p.get("serviceName") or p.get("service_name") or ""}


def _group_names(nodes: list[dict], names: list[str]) -> dict[str, list[str]]:
    groups: dict[str, list[str]] = {}
    for c, n in zip(nodes, names, strict=True):
        if c.get("country"):
            groups.setdefault(f"{flag(c['country'])} {country_name(c['country'])}", []).append(n)
    return {k: v for k, v in groups.items() if len(v) >= 2}


def render_clash(nodes: list[dict], title: str = "XFreedom") -> tuple[str, int]:
    names = display_names(nodes)
    entries = [(c, clash_proxy(c, n)) for c, n in zip(nodes, names, strict=True)]
    proxies = [e for _, e in entries if e]
    pnames = [e["name"] for e in proxies]
    kept = [c for c, e in entries if e]
    main_g, auto_g, fb_g, ru_g = f"🚀 {title}", "⚡ Авто (быстрейший)", "🔁 Резерв", "🎯 РФ напрямую"
    groups_by_country = _group_names(kept, pnames)
    lines = [
        "mixed-port: 7890", "allow-lan: false", "mode: rule", "log-level: warning", "ipv6: false",
        "unified-delay: true", "tcp-concurrent: true", "find-process-mode: off",
        "geodata-mode: false",
        "dns:",
        "  enable: true", "  ipv6: false", "  enhanced-mode: fake-ip", "  fake-ip-range: 198.18.0.1/16",
        f"  default-nameserver: {_y(['1.1.1.1', '8.8.8.8'])}",
        f"  nameserver: {_y([DNS_REMOTE, 'https://dns.google/dns-query'])}",
        f"  nameserver-policy: {_y({'+.ru': [DNS_DOMESTIC], '+.su': [DNS_DOMESTIC], '+.xn--p1ai': [DNS_DOMESTIC]})}",
        f"  fake-ip-filter: {_y(['*.lan', '+.local', '+.ru', '+.su', '+.xn--p1ai', 'time.*.com', 'time.*.gov', 'pool.ntp.org', '+.msftconnecttest.com'])}",
        "proxies:",
    ]
    lines += [f"  - {_y(p)}" for p in proxies]
    lines.append("proxy-groups:")
    group_list = [
        {"name": main_g, "type": "select", "proxies": [auto_g, fb_g, *groups_by_country, *pnames]},
        {"name": auto_g, "type": "url-test", "url": CHECK_URL, "interval": 300, "tolerance": 50, "lazy": True, "proxies": pnames},
        {"name": fb_g, "type": "fallback", "url": CHECK_URL, "interval": 300, "proxies": pnames},
        {"name": ru_g, "type": "select", "proxies": ["DIRECT", main_g]},
    ]
    for gname, members in groups_by_country.items():
        group_list.append({"name": gname, "type": "url-test", "url": CHECK_URL, "interval": 300, "tolerance": 50,
                           "lazy": True, "proxies": members})
    lines += [f"  - {_y(g)}" for g in group_list]
    lines.append("rules:")
    rules = [f"DOMAIN-SUFFIX,{d},{ru_g}" for d in RU_DOMAIN_SUFFIXES]
    rules += ["GEOIP,PRIVATE,DIRECT,no-resolve", f"GEOIP,RU,{ru_g}", f"MATCH,{main_g}"]
    lines += [f"  - {r}" for r in rules]
    return "\n".join(lines) + "\n", len(proxies)


# ---------------------------------------------------------------- sing-box
def _sb_tls(c: dict) -> dict | None:
    if c.get("is_reality"):
        if not c.get("pbk"):
            return None
        return {"enabled": True, "server_name": c.get("sni", ""),
                "utls": {"enabled": True, "fingerprint": norm_fp(c.get("fp"))},
                "reality": {"enabled": True, "public_key": c["pbk"], "short_id": c.get("sid", "")}}
    if c.get("is_tls"):
        tls = {"enabled": True, "server_name": c.get("sni") or c["host"], "insecure": True}
        if c.get("fp"):
            tls["utls"] = {"enabled": True, "fingerprint": norm_fp(c["fp"])}
        if _alpn(c):
            tls["alpn"] = _alpn(c)
        return tls
    return {}


def _sb_transport(net: str, p: dict) -> dict | None:
    if net == "ws":
        t: dict = {"type": "ws", "path": p.get("path") or "/"}
        if p.get("host"):
            t["headers"] = {"Host": p["host"]}
        return t
    if net == "grpc":
        return {"type": "grpc", "service_name": p.get("serviceName") or p.get("service_name") or ""}
    if net == "httpupgrade":
        return {"type": "httpupgrade", "path": p.get("path") or "/", "host": p.get("host", "")}
    return {} if net == "tcp" else None


def singbox_outbound(c: dict, tag: str) -> dict | None:
    t = c.get("type", "vless")
    p = _params(c)
    net = _net(c)
    base = {"tag": tag, "server": c["host"], "server_port": c["port"]}
    if t in ("vless", "vmess", "trojan"):
        transport = _sb_transport(net, p)
        tls = _sb_tls(c) if t != "trojan" else (_sb_tls(c) or {})
        if transport is None or tls is None:
            return None
        if t == "trojan" and c.get("is_reality"):
            return None
        d = {**base, "type": t}
        if t == "vless":
            d["uuid"] = c["uuid"]
            d["packet_encoding"] = "xudp"
            if c.get("flow"):
                d["flow"] = c["flow"]
        elif t == "vmess":
            d.update({"uuid": c["uuid"], "security": p.get("scy") or "auto", "alter_id": int(p.get("aid", 0) or 0)})
        else:
            d["password"] = c["password"]
        if tls:
            d["tls"] = tls
        if transport:
            d["transport"] = transport
        return d
    if t == "ss":
        if c.get("plugin"):
            return None
        return {**base, "type": "shadowsocks", "method": c["method"], "password": c["password"]}
    if t == "hysteria2":
        d = {**base, "type": "hysteria2", "password": c["password"],
             "tls": {"enabled": True, "server_name": c.get("sni") or c["host"], "insecure": True}}
        if p.get("obfs"):
            d["obfs"] = {"type": p["obfs"], "password": p.get("obfs-password", "")}
        return d
    if t == "tuic":
        return {**base, "type": "tuic", "uuid": c["uuid"], "password": c.get("password", ""),
                "congestion_control": p.get("congestion_control", "bbr"),
                "udp_relay_mode": p.get("udp_relay_mode", "native"),
                "tls": {"enabled": True, "server_name": c.get("sni") or c["host"], "insecure": True,
                        "alpn": _alpn(c) or ["h3"]}}
    return None


def render_singbox(nodes: list[dict], title: str = "XFreedom") -> tuple[str, int]:
    names = display_names(nodes)
    outs = []
    for c, n in zip(nodes, names, strict=True):
        o = singbox_outbound(c, n)
        if o:
            outs.append((c, o))
    tags = [o["tag"] for _, o in outs]
    main_g, auto_g = f"🚀 {title}", "⚡ Авто (быстрейший)"
    country_groups = _group_names([c for c, _ in outs], tags)
    selector = {"type": "selector", "tag": main_g, "outbounds": [auto_g, *country_groups, *tags], "default": auto_g}
    urltest = {"type": "urltest", "tag": auto_g, "outbounds": tags, "url": CHECK_URL, "interval": "5m", "tolerance": 50}
    extra = [{"type": "urltest", "tag": g, "outbounds": m, "url": CHECK_URL, "interval": "5m", "tolerance": 50}
             for g, m in country_groups.items()]
    cfg = {
        "log": {"level": "warn", "timestamp": True},
        "dns": {
            "servers": [
                {"type": "https", "tag": "dns-remote", "server": "1.1.1.1", "detour": main_g},
                {"type": "udp", "tag": "dns-direct", "server": DNS_DOMESTIC},
            ],
            "rules": [{"domain_suffix": [f".{d}" for d in RU_DOMAIN_SUFFIXES if d != "local"], "server": "dns-direct"}],
            "final": "dns-remote",
            "strategy": "ipv4_only",
        },
        "inbounds": [
            {"type": "tun", "tag": "tun-in", "address": ["172.19.0.1/30"], "auto_route": True,
             "strict_route": True, "stack": "mixed"},
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080},
        ],
        "outbounds": [selector, urltest, *extra, *[o for _, o in outs], {"type": "direct", "tag": "direct"}],
        "route": {
            "rules": [
                {"action": "sniff"},
                {"protocol": "dns", "action": "hijack-dns"},
                {"ip_is_private": True, "outbound": "direct"},
                {"domain_suffix": [f".{d}" for d in RU_DOMAIN_SUFFIXES], "outbound": "direct"},
                {"rule_set": "geoip-ru", "outbound": "direct"},
            ],
            "rule_set": [{"type": "remote", "tag": "geoip-ru", "format": "binary", "url": GEOIP_RU_SRS,
                          "download_detour": "direct"}],
            "final": main_g,
            "auto_detect_interface": True,
            "default_domain_resolver": "dns-direct",
        },
        "experimental": {"cache_file": {"enabled": True}},
    }
    return json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", len(outs)


# ---------------------------------------------------------------- xray
def xray_outbound(c: dict) -> dict | None:
    t = c.get("type", "vless")
    p = _params(c)
    net = _net(c)
    if t not in ("vless", "vmess", "trojan", "ss"):
        return None
    if net not in ("tcp", "ws", "grpc", "xhttp", "httpupgrade"):
        return None
    if t == "ss":
        if c.get("plugin"):
            return None
        return {"tag": "proxy", "protocol": "shadowsocks", "settings": {"servers": [
            {"address": c["host"], "port": c["port"], "method": c["method"], "password": c["password"]}]}}
    stream: dict = {"network": net}
    if c.get("is_reality"):
        if not c.get("pbk") or t == "trojan":
            return None
        stream["security"] = "reality"
        stream["realitySettings"] = {"serverName": c.get("sni", ""), "fingerprint": norm_fp(c.get("fp")),
                                     "publicKey": c["pbk"], "shortId": c.get("sid", ""), "spiderX": p.get("spx", "/")}
    elif c.get("is_tls"):
        if c.get("cert_ok") is False:
            return None  # Xray 26+ dropped allowInsecure, a node with an invalid certificate cannot work there
        stream["security"] = "tls"
        tls = {"serverName": c.get("sni") or c["host"]}
        if c.get("fp"):
            tls["fingerprint"] = norm_fp(c["fp"])
        if _alpn(c):
            tls["alpn"] = _alpn(c)
        stream["tlsSettings"] = tls
    else:
        stream["security"] = "none"
    if net == "ws":
        ws = {"path": p.get("path") or "/"}
        if p.get("host"):
            ws["headers"] = {"Host": p["host"]}
        stream["wsSettings"] = ws
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": p.get("serviceName") or p.get("service_name") or ""}
    elif net == "xhttp":
        x = {"path": p.get("path") or "/", "mode": p.get("mode") or "auto"}
        if p.get("host"):
            x["host"] = p["host"]
        stream["xhttpSettings"] = x
    elif net == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": p.get("path") or "/", "host": p.get("host", "")}
    if t == "vless":
        user = {"id": c["uuid"], "encryption": "none"}
        if c.get("flow"):
            user["flow"] = c["flow"]
        settings = {"vnext": [{"address": c["host"], "port": c["port"], "users": [user]}]}
    elif t == "vmess":
        settings = {"vnext": [{"address": c["host"], "port": c["port"], "users": [
            {"id": c["uuid"], "alterId": int(p.get("aid", 0) or 0), "security": p.get("scy") or "auto"}]}]}
    else:
        settings = {"servers": [{"address": c["host"], "port": c["port"], "password": c["password"]}]}
    return {"tag": "proxy", "protocol": t, "settings": settings, "streamSettings": stream}


def render_xray(nodes: list[dict], title: str = "XFreedom") -> tuple[str, int]:
    names = display_names(nodes)
    configs = []
    for c, n in zip(nodes, names, strict=True):
        ob = xray_outbound(c)
        if not ob:
            continue
        configs.append({
            "remarks": n,
            "log": {"loglevel": "warning"},
            "dns": {"servers": [DNS_REMOTE, {"address": DNS_DOMESTIC, "domains": [f"domain:{d}" for d in RU_DOMAIN_SUFFIXES if d != "local"],
                                             "expectIPs": ["geoip:ru"]}], "queryStrategy": "UseIPv4"},
            "inbounds": [
                {"tag": "socks", "listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": {"udp": True},
                 "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True}},
                {"tag": "http", "listen": "127.0.0.1", "port": 10809, "protocol": "http",
                 "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True}},
            ],
            "outbounds": [ob, {"tag": "direct", "protocol": "freedom"}, {"tag": "block", "protocol": "blackhole"}],
            "routing": {"domainStrategy": "IPIfNonMatch", "rules": [
                {"type": "field", "domain": [f"domain:{d}" for d in RU_DOMAIN_SUFFIXES], "outboundTag": "direct"},
                {"type": "field", "ip": ["geoip:private", "geoip:ru"], "outboundTag": "direct"},
                {"type": "field", "network": "tcp,udp", "outboundTag": "proxy"},
            ]},
        })
    return json.dumps(configs, ensure_ascii=False, indent=2) + "\n", len(configs)


# ---------------------------------------------------------------- uri lists
def render_uri(nodes: list[dict], headers_in_body: dict[str, str] | None = None) -> tuple[str, int]:
    names = display_names(nodes)
    lines = [f"//{k}: {v}" for k, v in (headers_in_body or {}).items()]
    if lines:
        lines.append("")
    lines += [with_name(c["raw"], n) for c, n in zip(nodes, names, strict=True)]
    return "\n".join(lines) + "\n", len(nodes)


def render_base64(nodes: list[dict]) -> tuple[str, int]:
    text, n = render_uri(nodes)
    return base64.b64encode(text.strip().encode()).decode(), n


def render(fmt: str, nodes: list[dict], title: str = "XFreedom", body_headers: dict[str, str] | None = None) -> tuple[str, int]:
    if fmt == "clash":
        return render_clash(nodes, title)
    if fmt == "singbox":
        return render_singbox(nodes, title)
    if fmt == "xray":
        return render_xray(nodes, title)
    if fmt == "uri":
        return render_uri(nodes, body_headers)
    return render_base64(nodes)


# ---------------------------------------------------------------- headers
def b64_header(text: str) -> str:
    return "base64:" + base64.b64encode(text.encode()).decode()


def happ_routing_header() -> str:
    """Happ-style routing profile: Russian sites and IPs direct, the rest proxied."""
    profile = {
        "Name": "XFreedom RU direct", "GlobalProxy": "true", "DomainStrategy": "IPIfNonMatch",
        "RemoteDNSType": "DoH", "RemoteDNSDomain": "", "RemoteDNSIP": "1.1.1.1",
        "DomesticDNSType": "DoU", "DomesticDNSDomain": "", "DomesticDNSIP": DNS_DOMESTIC,
        "DirectSites": [f"domain:{d}" for d in RU_DOMAIN_SUFFIXES if d != "local"],
        "DirectIp": ["geoip:private", "geoip:ru"], "ProxySites": [], "ProxyIp": [], "BlockSites": [], "BlockIp": [],
        "FakeDNS": "false", "LastUpdated": str(int(time.time())),
    }
    return "happ://routing/onadd/" + base64.b64encode(json.dumps(profile, ensure_ascii=False).encode()).decode()


def build_headers(fmt: str, *, title: str, interval: int, support_url: str, web_page: str, announce: str,
                  total: int, expire: int, refill: int | None, live: int, checked: int, filename: str) -> dict[str, str]:
    h = {
        "profile-title": b64_header(title),
        "profile-update-interval": str(interval),
        "subscription-userinfo": f"upload=0; download=0; total={total}; expire={expire}",
        "support-url": support_url,
        "profile-web-page-url": web_page,
        "announce": b64_header(announce),
        "routing": happ_routing_header(),
        "content-disposition": f'attachment; filename="{filename}"; filename*=UTF-8\'\'{quote(filename)}',
        "x-live-nodes": str(live),
        "x-checked-nodes": str(checked),
        "cache-control": "no-store",
    }
    if refill:
        h["subscription-refill-date"] = str(refill)
    return h


_UA_SAFE = re.compile(r"[^a-z0-9._-]+")


def safe_filename(title: str, fmt: str) -> str:
    return f"{_UA_SAFE.sub('-', title.lower()).strip('-') or 'sub'}-{fmt}.{EXTENSIONS[fmt]}"
