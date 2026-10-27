"""
Telegram Bot for Proxy Subscription Service
- /start — get subscription links
- /lte, /wifi, /3g — network-specific configs
- /stats — config statistics
- /sources — manage config sources (admin)
- WebApp button — opens Mini App UI
"""

import asyncio
import logging
import os

import httpx
from aiogram import Bot, Dispatcher, F, types
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.filters import Command, CommandStart
from aiogram.types import (
    BotCommand,
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    WebAppInfo,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
API_BASE = os.getenv("PROXY_SUB_API", "http://127.0.0.1:8000")
WEBAPP_URL = os.getenv("WEBAPP_URL", "")
# Public URL that Telegram users can open (API_BASE is usually a local address).
PUBLIC_URL = os.getenv("PUBLIC_URL", "").rstrip("/")
REFRESH_TOKEN = os.getenv("REFRESH_TOKEN", "")


def parse_admin_ids(raw: str) -> set[int]:
    ids = set()
    for part in raw.replace(" ", "").split(","):
        if part.lstrip("-").isdigit():
            ids.add(int(part))
        elif part:
            logger.warning("Ignoring invalid ADMIN_IDS entry: %r", part)
    return ids


ADMIN_IDS = parse_admin_ids(os.getenv("ADMIN_IDS", ""))

dp = Dispatcher()


def public_base() -> str:
    return PUBLIC_URL or API_BASE.rstrip("/")


def is_public_url(url: str) -> bool:
    """Telegram rejects URL buttons pointing to localhost/private hosts."""
    from urllib.parse import urlparse
    host = (urlparse(url).hostname or "").lower()
    if not host or host == "localhost" or host.endswith(".local"):
        return False
    import ipaddress
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        return True


LINK_SCHEMES = ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "tuic://")


def stats_extra(data: dict) -> str:
    """Health and geography lines shared by the /stats command and the stats button."""
    hl = data.get("health") or {}
    lines = []
    if hl:
        lines.append(
            f"✅ Живых: <b>{hl.get('alive', 0)}</b> · мёртвых: {hl.get('dead', 0)} · "
            f"медиана: {hl.get('latency_ms_median') or '—'} мс"
        )
    proto = data.get("by_protocol") or {}
    if proto:
        lines.append("Протоколы: " + ", ".join(f"{k} {v}" for k, v in sorted(proto.items(), key=lambda kv: -kv[1])))
    countries = data.get("by_country") or {}
    if countries:
        lines.append("Страны: " + ", ".join(f"{k} {v}" for k, v in list(countries.items())[:8]))
    return "\n".join(lines)


def user_id(obj) -> int | None:
    return obj.from_user.id if obj.from_user else None


async def api_get(path: str, with_headers: bool = False):
    """GET from the local API; with ``with_headers`` returns ``(body, headers)``."""
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.get(f"{API_BASE}{path}")
            if resp.status_code == 200:
                ct = resp.headers.get("content-type", "")
                body = resp.json() if "json" in ct and "format=" not in path else resp.text
                return (body, resp.headers) if with_headers else body
    except Exception as e:
        logger.error(f"API error: {e}")
    return (None, {}) if with_headers else None


def main_keyboard() -> InlineKeyboardMarkup:
    buttons = [
        [
            InlineKeyboardButton(text="📡 LTE", callback_data="sub_lte"),
            InlineKeyboardButton(text="🌐 WiFi", callback_data="sub_wifi"),
            InlineKeyboardButton(text="📶 3G", callback_data="sub_3g"),
        ],
        [
            InlineKeyboardButton(text="🔄 Лучшие", callback_data="sub_best"),
            InlineKeyboardButton(text="📊 Статистика", callback_data="stats"),
        ],
    ]
    if WEBAPP_URL:
        buttons.append([
            InlineKeyboardButton(
                text="🌍 Открыть WebApp",
                web_app=WebAppInfo(url=WEBAPP_URL),
            )
        ])
    return InlineKeyboardMarkup(inline_keyboard=buttons)


def admin_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="📋 Источники", callback_data="admin_sources"),
            InlineKeyboardButton(text="🔄 Обновить кэш", callback_data="admin_refresh"),
        ],
        [InlineKeyboardButton(text="« Назад", callback_data="back_main")],
    ])


def sub_url_for(network: str, fmt: str = "") -> str:
    return f"{public_base()}/sub/{network}" + (f"?format={fmt}" if fmt else "")


FORMAT_BUTTONS = (("Clash / Mihomo", "clash"), ("sing-box", "singbox"), ("Xray JSON", "xray"))


def sub_link_keyboard(network: str) -> InlineKeyboardMarkup:
    sub_url = sub_url_for(network)
    rows = []
    if is_public_url(sub_url):
        rows.append([InlineKeyboardButton(text="🔗 Открыть ссылку подписки", url=sub_url)])
        rows.append([InlineKeyboardButton(text=label, url=sub_url_for(network, fmt)) for label, fmt in FORMAT_BUTTONS])
    rows.append([InlineKeyboardButton(text="« Назад", callback_data="back_main")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


@dp.message(CommandStart())
async def cmd_start(message: types.Message):
    is_admin = user_id(message) in ADMIN_IDS
    text = (
        "🔑 <b>Proxy Subscription Bot</b>\n\n"
        "Автоматические прокси-конфигурации для Hiddify.\n"
        "Выбери тип сети для получения подписки:\n\n"
        "📡 <b>LTE</b> — REALITY/VISION, порт 443\n"
        "🌐 <b>WiFi</b> — WS/TLS через CDN\n"
        "📶 <b>3G</b> — gRPC, стабильное соединение\n"
        "🔄 <b>Лучшие</b> — топ-20 по качеству\n"
    )
    if is_admin:
        text += "\n🔧 Ты админ — /admin для управления"
    await message.answer(text, reply_markup=main_keyboard())


@dp.message(Command("admin"))
async def cmd_admin(message: types.Message):
    if user_id(message) not in ADMIN_IDS:
        await message.answer("⛔ Нет доступа")
        return
    await message.answer("🔧 <b>Панель управления</b>", reply_markup=admin_keyboard())


@dp.message(Command("lte"))
async def cmd_lte(message: types.Message):
    await send_subscription(message, "lte", "📡 LTE")


@dp.message(Command("wifi"))
async def cmd_wifi(message: types.Message):
    await send_subscription(message, "wifi", "🌐 WiFi")


@dp.message(Command("3g"))
async def cmd_3g(message: types.Message):
    await send_subscription(message, "3g", "📶 3G")


@dp.message(Command("best"))
async def cmd_best(message: types.Message):
    await send_subscription(message, "best", "🔄 Лучшие")


@dp.message(Command("stats"))
async def cmd_stats(message: types.Message):
    data = await api_get("/stats")
    if not data or not isinstance(data, dict):
        await message.answer("❌ Не удалось получить статистику")
        return
    text = (
        f"📊 <b>Статистика конфигов</b>\n\n"
        f"Всего: <b>{data['total_configs']}</b>\n"
        f"├ REALITY: {data['by_type']['reality']}\n"
        f"├ REALITY+VISION: {data['by_type']['reality_vision']}\n"
        f"├ WS/TLS: {data['by_type']['ws_tls']}\n"
        f"├ gRPC: {data['by_type']['grpc']}\n"
        f"└ Shadowsocks: {data['by_type']['shadowsocks']}\n\n"
        f"<b>По сетям:</b>\n"
        f"📡 LTE: {data['by_network']['lte']}\n"
        f"🌐 WiFi: {data['by_network']['wifi']}\n"
        f"📶 3G: {data['by_network']['3g']}\n\n"
        f"{stats_extra(data)}\n\n"
        f"Источников: {data.get('sources_ok', data['sources_count'])}/{data['sources_count']} работают\n"
        f"Обновлено: {data.get('last_update') or 'N/A'}"
    )
    await message.answer(text)


async def send_subscription(message: types.Message, network: str, label: str):
    wait_msg = await message.answer(f"⏳ Загружаю {label} конфиги...")
    data, headers = await api_get(f"/sub/{network}?format=uri", with_headers=True)
    if not data:
        await wait_msg.edit_text(f"❌ Не удалось загрузить {label} конфиги")
        return

    lines = [ln for ln in str(data).splitlines() if ln.startswith(LINK_SCHEMES)]
    count = len(lines)
    live = headers.get("x-live-nodes", "?")
    sub_url = sub_url_for(network)

    text = (
        f"{label} <b>Подписка</b>\n\n"
        f"Узлов: <b>{count}</b> (проверено живых: <b>{live}</b>)\n\n"
        f"<b>Как добавить:</b>\n"
        f"1. Открой клиент (Hiddify, v2rayNG, Happ, Clash, sing-box)\n"
        f"2. Нажми + → Добавить подписку\n"
        f"3. Вставь ссылку:\n"
        f"<code>{sub_url}</code>\n\n"
        f"Формат выбирается по клиенту автоматически. Кнопки ниже — прямые ссылки на Clash, sing-box и Xray JSON.\n"
        f"Подписка обновляется каждый час, узлы перепроверяются каждые 10 минут."
    )
    await wait_msg.edit_text(text, reply_markup=sub_link_keyboard(network))


# === Callbacks ===

@dp.callback_query(F.data == "sub_lte")
async def cb_lte(callback: CallbackQuery):
    await callback.answer()
    await send_sub_callback(callback, "lte", "📡 LTE")


@dp.callback_query(F.data == "sub_wifi")
async def cb_wifi(callback: CallbackQuery):
    await callback.answer()
    await send_sub_callback(callback, "wifi", "🌐 WiFi")


@dp.callback_query(F.data == "sub_3g")
async def cb_3g(callback: CallbackQuery):
    await callback.answer()
    await send_sub_callback(callback, "3g", "📶 3G")


@dp.callback_query(F.data == "sub_best")
async def cb_best(callback: CallbackQuery):
    await callback.answer()
    await send_sub_callback(callback, "best", "🔄 Лучшие")


@dp.callback_query(F.data == "stats")
async def cb_stats(callback: CallbackQuery):
    await callback.answer()
    data = await api_get("/stats")
    if not data or not isinstance(data, dict):
        await callback.message.edit_text("❌ Ошибка", reply_markup=main_keyboard())
        return
    text = (
        f"📊 <b>Статистика</b>\n\n"
        f"Всего: <b>{data['total_configs']}</b>\n"
        f"REALITY: {data['by_type']['reality']} | "
        f"WS/TLS: {data['by_type']['ws_tls']} | "
        f"SS: {data['by_type']['shadowsocks']}\n\n"
        f"📡 LTE: {data['by_network']['lte']} | "
        f"🌐 WiFi: {data['by_network']['wifi']} | "
        f"📶 3G: {data['by_network']['3g']}\n\n"
        f"{stats_extra(data)}"
    )
    await callback.message.edit_text(text, reply_markup=InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="« Назад", callback_data="back_main")],
    ]))


@dp.callback_query(F.data == "back_main")
async def cb_back(callback: CallbackQuery):
    await callback.answer()
    await callback.message.edit_text(
        "🔑 <b>Proxy Subscription Bot</b>\n\nВыбери тип сети:",
        reply_markup=main_keyboard(),
    )


@dp.callback_query(F.data == "admin_sources")
async def cb_sources(callback: CallbackQuery):
    if user_id(callback) not in ADMIN_IDS:
        await callback.answer("⛔ Нет доступа", show_alert=True)
        return
    await callback.answer()
    data = await api_get("/stats")
    if data and isinstance(data, dict):
        text = f"📋 <b>Источники: {data['sources_count']}</b>\n\nДля управления источниками используй веб-панель."
    else:
        text = "❌ Ошибка"
    await callback.message.edit_text(text, reply_markup=admin_keyboard())


@dp.callback_query(F.data == "admin_refresh")
async def cb_refresh(callback: CallbackQuery):
    if user_id(callback) not in ADMIN_IDS:
        await callback.answer("⛔ Нет доступа", show_alert=True)
        return
    await callback.answer("🔄 Обновляю...")
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            headers = {"X-Refresh-Token": REFRESH_TOKEN} if REFRESH_TOKEN else {}
            resp = await client.post(f"{API_BASE}/refresh", headers=headers)
            resp.raise_for_status()
            total = resp.json().get("total_configs", 0)
        await callback.message.edit_text(f"✅ Кэш обновлён: {total} конфигов", reply_markup=admin_keyboard())
    except Exception:
        await callback.message.edit_text("❌ Ошибка обновления", reply_markup=admin_keyboard())


async def send_sub_callback(callback: CallbackQuery, network: str, label: str):
    await callback.message.edit_text(f"⏳ Загружаю {label}...")
    path = f"/sub/{network}"
    data = await api_get(path)
    if not data:
        await callback.message.edit_text("❌ Ошибка", reply_markup=main_keyboard())
        return
    lines = [ln for ln in str(data).splitlines() if ln.startswith(("vless://", "ss://"))]
    sub_url = sub_url_for(network)
    text = (
        f"{label} <b>Подписка</b> ({len(lines)} конфигов)\n\n"
        f"<b>Ссылка для Hiddify:</b>\n"
        f"<code>{sub_url}</code>\n\n"
        f"Нажми на ссылку чтобы скопировать."
    )
    await callback.message.edit_text(text, reply_markup=sub_link_keyboard(network))


async def set_commands(bot: Bot):
    commands = [
        BotCommand(command="start", description="Главное меню"),
        BotCommand(command="lte", description="📡 LTE конфиги"),
        BotCommand(command="wifi", description="🌐 WiFi конфиги"),
        BotCommand(command="3g", description="📶 3G конфиги"),
        BotCommand(command="best", description="🔄 Лучшие конфиги"),
        BotCommand(command="stats", description="📊 Статистика"),
    ]
    await bot.set_my_commands(commands)


async def main():
    if not BOT_TOKEN:
        logger.error("TELEGRAM_BOT_TOKEN not set!")
        return
    bot = Bot(token=BOT_TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    await set_commands(bot)
    logger.info("Bot starting...")
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
