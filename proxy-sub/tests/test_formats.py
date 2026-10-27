import base64
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import formats  # noqa: E402
import geo  # noqa: E402
import main  # noqa: E402
import nodes  # noqa: E402

VLESS = ("vless://uuid-1@a.example.com:443?security=reality&type=tcp&flow=xtls-rprx-vision"
         "&sni=www.yandex.ru&fp=chrome&pbk=KEY&sid=ab#n1")
VLESS_WS = "vless://uuid-2@b.example.com:443?security=tls&type=ws&path=%2Fws&host=b.example.com&sni=b.example.com#n2"
VLESS_GRPC = "vless://uuid-3@c.example.com:443?security=tls&type=grpc&serviceName=svc&sni=c.example.com#n3"
VLESS_XHTTP = "vless://uuid-4@d.example.com:443?security=tls&type=xhttp&path=%2Fx&host=d.example.com&sni=d.example.com#n4"
SS = "ss://chacha20-ietf-poly1305:secret@e.example.com:8443#n5"
TROJAN = "trojan://pw@f.example.com:443?sni=f.example.com&type=tcp#n6"
HY2 = "hysteria2://pw@g.example.com:443?sni=g.example.com&insecure=1#n7"
TUIC = "tuic://uuid:pw@h.example.com:443?sni=h.example.com&congestion_control=bbr&alpn=h3#n8"
VMESS = "vmess://" + base64.b64encode(json.dumps({
    "v": "2", "ps": "n9", "add": "i.example.com", "port": "443", "id": "11111111-1111-1111-1111-111111111111",
    "aid": "0", "net": "ws", "type": "none", "host": "i.example.com", "path": "/v", "tls": "tls", "sni": "i.example.com",
}).encode()).decode()


def all_nodes():
    out = [main.parse_line(x) for x in (VLESS, VLESS_WS, VLESS_GRPC, VLESS_XHTTP, SS, TROJAN, HY2, TUIC, VMESS)]
    assert all(out), "every sample line must parse"
    for i, c in enumerate(out):
        c["country"] = ["DE", "NL", "US", "FR", "RU", "DE", "JP", "SG", "GB"][i]
    return out


# ------------------------------------------------------------ parsers
def test_parse_vmess_ws_tls():
    c = nodes.parse_vmess(VMESS)
    assert c["type"] == "vmess" and c["host"] == "i.example.com" and c["port"] == 443
    assert c["is_tls"] and c["params"]["path"] == "/v"


def test_parse_vmess_rejects_garbage():
    assert nodes.parse_vmess("vmess://@@@") is None


def test_parse_trojan_hy2_tuic():
    t = nodes.parse_trojan(TROJAN)
    assert t["type"] == "trojan" and t["sni"] == "f.example.com"
    h = nodes.parse_hysteria2(HY2)
    assert h["type"] == "hysteria2" and h["port"] == 443
    u = nodes.parse_tuic(TUIC)
    assert u["type"] == "tuic" and u["host"] == "h.example.com"


def test_hysteria2_alias_scheme():
    assert nodes.scheme_of("hy2://x@h:1#a") == "hysteria2"
    assert nodes.scheme_of("http://x") is None


def test_legacy_ss_cipher_rejected():
    assert main.parse_ss("ss://aes-256-cfb:pw@1.2.3.4:443#old") is None
    assert main.parse_ss(SS) is not None


def test_dedupe_same_endpoint_keeps_best():
    a = main.parse_line(VLESS)
    b = main.parse_line(VLESS.replace("uuid-1", "uuid-other"))
    b["score"] = a["score"] + 5
    out = main.dedupe([a, b, dict(a)])
    assert len(out) == 1 and out[0] is b


# ------------------------------------------------------------ format detection
@pytest.mark.parametrize("ua,expected", [
    ("clash.meta/1.18", "clash"), ("mihomo/1.19", "clash"), ("ClashX Pro", "clash"), ("Stash/2.5", "clash"),
    ("sing-box 1.12", "singbox"), ("SFA/1.9", "singbox"), ("Hiddify/2.0", "base64"), ("v2rayNG/1.9", "base64"),
    ("Happ/1.0", "base64"), ("Mozilla/5.0 (X11) Chrome/120", "uri"), ("", "base64"), (None, "base64"),
    ("v2rayN-json", "xray"),
])
def test_detect_format_by_ua(ua, expected):
    assert formats.detect_format(ua) == expected


def test_explicit_format_wins_and_junk_ignored():
    assert formats.detect_format("clash.meta", "xray") == "xray"
    assert formats.detect_format("clash.meta", "bogus") == "clash"


# ------------------------------------------------------------ naming
def test_display_names_have_flags_and_unique_indexes():
    ns = all_nodes()
    ns.append(dict(ns[0]))
    names = formats.display_names(ns)
    assert len(set(names)) == len(names)
    assert names[0].startswith("🇩🇪 Германия")
    assert names[4].startswith("🇷🇺")


def test_flag_and_country_helpers():
    assert geo.flag("DE") == "🇩🇪" and geo.flag(None) == "🌐" and geo.flag("xx1") == "🌐"
    assert geo.country_name("DE") == "Германия" and geo.country_name(None) == "Неизвестно"
    assert geo.country_from_name("🇫🇷 Paris 1") == "FR"
    assert geo.country_from_name("no flag") is None


def test_norm_fp_fallback():
    assert formats.norm_fp("unsafe") == "chrome" and formats.norm_fp(None) == "chrome"
    assert formats.norm_fp("firefox") == "firefox"
    assert formats.norm_fp("randomized", clash=True) == "random"


# ------------------------------------------------------------ renderers
def test_render_uri_keeps_meta_and_names():
    text, n = formats.render_uri(all_nodes(), {"profile-title": "base64:x"})
    assert n == 9 and text.startswith("//profile-title: base64:x")
    assert text.count("://") >= 9


def test_render_base64_roundtrip():
    text, n = formats.render_base64(all_nodes())
    decoded = base64.b64decode(text).decode()
    assert n == 9 and len([ln for ln in decoded.splitlines() if "://" in ln]) == 9


def test_render_clash_structure_and_rules():
    import yaml
    text, n = formats.render_clash(all_nodes())
    doc = yaml.safe_load(text)
    assert n == len(doc["proxies"]) == 8  # XHTTP cannot be expressed in Clash
    types = {p["type"] for p in doc["proxies"]}
    assert {"vless", "ss", "trojan", "hysteria2", "tuic", "vmess"} <= types
    group_names = [g["name"] for g in doc["proxy-groups"]]
    assert len(group_names) == len(set(group_names)), "mihomo rejects duplicate group names"
    assert len(doc["rules"]) >= 20 and doc["rules"][-1].startswith("MATCH")
    assert any("geoip,ru" in r.lower() for r in doc["rules"])
    known = set(group_names) | {"DIRECT", "REJECT"}
    for r in doc["rules"]:
        target = r.split(",")[2] if r.startswith(("DOMAIN", "GEOIP", "GEOSITE")) else r.split(",")[-1]
        assert target.replace(",no-resolve", "") in known or r.startswith("MATCH")
    assert doc["dns"]["enable"] is True


def test_render_singbox_structure():
    doc = json.loads(formats.render_singbox(all_nodes())[0])
    tags = {o["tag"] for o in doc["outbounds"]}
    assert {"direct", "select"} <= tags or "direct" in tags
    types = {o["type"] for o in doc["outbounds"]}
    assert {"vless", "shadowsocks", "trojan", "hysteria2", "tuic", "vmess"} <= types
    assert doc["route"]["rules"], "routing rules expected"
    assert all(o["type"] != "vless" or o.get("server") for o in doc["outbounds"])


def test_render_xray_configs_are_per_node_and_skip_bad_cert():
    ns = all_nodes()
    ns[1]["cert_ok"] = False  # tls node with an invalid certificate: Xray 26+ cannot connect
    configs = json.loads(formats.render_xray(ns)[0])
    names = {c["remarks"] for c in configs}
    assert len(configs) == 6  # 9 - hysteria2 - tuic - one node with a bad certificate
    assert not any("Hysteria" in n or "TUIC" in n for n in names)
    for c in configs:
        assert c["outbounds"][0]["tag"] == "proxy"
        assert "allowInsecure" not in json.dumps(c)
        assert c["routing"]["rules"]
    reality = next(c for c in configs if c["outbounds"][0]["streamSettings"]["security"] == "reality")
    assert reality["outbounds"][0]["streamSettings"]["realitySettings"]["publicKey"] == "KEY"


def test_xray_outbound_transports():
    ns = all_nodes()
    nets = {formats.xray_outbound(c)["streamSettings"]["network"] for c in ns if c["type"] == "vless"}
    assert {"tcp", "ws", "grpc"} <= nets
    assert any(n in nets for n in ("xhttp", "splithttp"))


# ------------------------------------------------------------ headers
def test_build_headers_complete():
    h = formats.build_headers("clash", title="XFreedom", interval=6, support_url="https://s", web_page="https://w",
                              announce="hi", total=100, expire=999, refill=555, live=40, checked=50,
                              filename="xfreedom-clash.yaml")
    for key in ("profile-title", "profile-update-interval", "subscription-userinfo", "support-url",
                "profile-web-page-url", "announce", "routing", "content-disposition", "subscription-refill-date"):
        assert h[key], key
    assert base64.b64decode(h["profile-title"].removeprefix("base64:")).decode() == "XFreedom"
    assert "total=100" in h["subscription-userinfo"] and "expire=999" in h["subscription-userinfo"]
    assert h["x-live-nodes"] == "40"


def test_happ_routing_header_decodes_to_ru_direct():
    hdr = formats.happ_routing_header()
    assert hdr.startswith("happ://routing/onadd/")
    profile = json.loads(base64.b64decode(hdr.split("/")[-1]))
    assert "geoip:ru" in profile["DirectIp"]
    assert "domain:ru" in profile["DirectSites"]


def test_safe_filename():
    assert formats.safe_filename("XFreedom LTE!", "clash") == "xfreedom-lte-clash.yaml"
    assert formats.safe_filename("🚀", "singbox").endswith(".json")
