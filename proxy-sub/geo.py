"""Country detection for proxy nodes (flag emoji in the name, else real IP geolocation).

Geolocation uses https://api.country.is (free, HTTPS, batch POST of up to 100 IPs).
Results are cached; when the lookup fails the node simply has no country.
"""

from __future__ import annotations

import asyncio
import os
import re
import socket
import time

import httpx

GEO_URL = os.getenv("GEO_URL", "https://api.country.is")
GEO_ENABLED = os.getenv("GEO_LOOKUP", "1") != "0"
GEO_TTL = 7 * 24 * 3600

_ip_cache: dict[str, tuple[str | None, float]] = {}
_FLAG_RE = re.compile("([\U0001F1E6-\U0001F1FF])([\U0001F1E6-\U0001F1FF])")

COUNTRY_RU = {
    "AE": "ОАЭ", "AL": "Албания", "AM": "Армения", "AR": "Аргентина", "AT": "Австрия", "AU": "Австралия",
    "AZ": "Азербайджан", "BA": "Босния", "BE": "Бельгия", "BG": "Болгария", "BR": "Бразилия", "BY": "Беларусь",
    "CA": "Канада", "CH": "Швейцария", "CL": "Чили", "CN": "Китай", "CY": "Кипр", "CZ": "Чехия",
    "DE": "Германия", "DK": "Дания", "EE": "Эстония", "ES": "Испания", "FI": "Финляндия", "FR": "Франция",
    "GB": "Великобритания", "GE": "Грузия", "GR": "Греция", "HK": "Гонконг", "HR": "Хорватия", "HU": "Венгрия",
    "ID": "Индонезия", "IE": "Ирландия", "IL": "Израиль", "IN": "Индия", "IR": "Иран", "IS": "Исландия",
    "IT": "Италия", "JP": "Япония", "KG": "Киргизия", "KR": "Корея", "KZ": "Казахстан", "LT": "Литва",
    "LU": "Люксембург", "LV": "Латвия", "MD": "Молдова", "MX": "Мексика", "MY": "Малайзия", "NL": "Нидерланды",
    "NO": "Норвегия", "NZ": "Новая Зеландия", "PL": "Польша", "PT": "Португалия", "RO": "Румыния", "RS": "Сербия",
    "RU": "Россия", "SA": "Саудовская Аравия", "SE": "Швеция", "SG": "Сингапур", "SI": "Словения", "SK": "Словакия",
    "TH": "Таиланд", "TR": "Турция", "TW": "Тайвань", "UA": "Украина", "US": "США", "UZ": "Узбекистан",
    "VN": "Вьетнам", "ZA": "ЮАР",
}


def flag(cc: str | None) -> str:
    if not cc or len(cc) != 2 or not cc.isalpha():
        return "🌐"
    return "".join(chr(0x1F1E6 + ord(ch) - ord("A")) for ch in cc.upper())


def country_name(cc: str | None) -> str:
    if not cc:
        return "Неизвестно"
    return COUNTRY_RU.get(cc.upper(), cc.upper())


def country_from_name(name: str) -> str | None:
    """A flag emoji already present in the node's own name is the cheapest signal."""
    m = _FLAG_RE.search(name or "")
    if not m:
        return None
    cc = "".join(chr(ord(g) - 0x1F1E6 + ord("A")) for g in m.groups())
    return cc if cc in COUNTRY_RU else None


async def _resolve_ip(host: str) -> str | None:
    try:
        socket.inet_pton(socket.AF_INET, host)
        return host
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return host
    except OSError:
        pass
    try:
        info = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
        return info[0][4][0]
    except OSError:
        return None


async def lookup_ips(ips: list[str], client: httpx.AsyncClient | None = None) -> dict[str, str]:
    """Batch-geolocate IPs through api.country.is; returns ip -> country code."""
    now = time.time()
    todo = [ip for ip in dict.fromkeys(ips) if ip not in _ip_cache or now - _ip_cache[ip][1] > GEO_TTL]
    own = client is None
    client = client or httpx.AsyncClient(timeout=20)
    try:
        for i in range(0, len(todo), 100):
            chunk = todo[i:i + 100]
            try:
                r = await client.post(GEO_URL, json=chunk)
                r.raise_for_status()
                got = {x["ip"]: x.get("country") for x in r.json() if isinstance(x, dict) and "ip" in x}
            except (httpx.HTTPError, ValueError, KeyError):
                continue
            for ip in chunk:
                _ip_cache[ip] = (got.get(ip), now)
    finally:
        if own:
            await client.aclose()
    return {ip: _ip_cache[ip][0] for ip in ips if ip in _ip_cache and _ip_cache[ip][0]}


async def annotate_countries(nodes: list[dict]) -> int:
    """Set ``country`` (ISO code or None) on every node; returns how many resolved."""
    pending: list[dict] = []
    for c in nodes:
        if c.get("country"):
            continue
        cc = country_from_name(c.get("name", ""))
        if cc:
            c["country"] = cc
        else:
            pending.append(c)
    if pending and GEO_ENABLED:
        hosts = list({c["host"] for c in pending})
        sem = asyncio.Semaphore(50)

        async def res(h: str) -> tuple[str, str | None]:
            async with sem:
                return h, await _resolve_ip(h)

        host_ip = dict(await asyncio.gather(*(res(h) for h in hosts)))
        found = await lookup_ips([ip for ip in host_ip.values() if ip])
        for c in pending:
            ip = host_ip.get(c["host"])
            c["country"] = found.get(ip) if ip else None
    return sum(1 for c in nodes if c.get("country"))
