# Proxy Subscription Service

Автоматический сервис подписки для Hiddify: **API + Telegram Bot + WebApp**.

## Возможности

- Автосбор из 8 источников (в наших замерах — тысячи узлов в пуле), дедупликация по endpoint и по учётным данным
- **Проверка живости**: TLS-рукопожатие для REALITY/TLS-узлов (с проверкой сертификата), TCP для остальных;
  мёртвые узлы в подписку не попадают, остальные сортируются по измеренной задержке
- **Протоколы**: VLESS (REALITY/Vision, WS, gRPC, XHTTP), VMess, Trojan, Shadowsocks (только AEAD), Hysteria2, TUIC
- **Форматы под клиент** (по `User-Agent` или `?format=`): универсальная base64-подписка, список ссылок, Clash/Mihomo YAML,
  sing-box JSON (1.12+), Xray JSON (по конфигу на узел)
- **Заголовки подписки**: `subscription-userinfo`, `profile-title`, `profile-update-interval`, `support-url`,
  `profile-web-page-url`, `announce`, `routing` (Happ), `content-disposition`, `x-live-nodes`
- **Маршрутизация**: российские домены и `geoip:ru` напрямую, реклама блокируется, остальное через прокси
  (Clash — правила и группы по странам, sing-box — route rules, Xray — routing)
- **Названия** вида `🇩🇪 Германия · Reality-Vision #1`, страна определяется по IP (api.country.is), лимиты на страну и хост
- **Telegram бот** и **WebApp** (выбор формата, статистика живости)

## Быстрая установка (Linux VPS)

```bash
curl -sL https://raw.githubusercontent.com/plojdjqpe-hash/AiMa/devin/1777773350-add-claude-code-skill/proxy-sub/install.sh | sudo bash
```

Или вручную:

```bash
git clone https://github.com/plojdjqpe-hash/AiMa.git
cd AiMa/proxy-sub
sudo bash install.sh
```

Скрипт установит:
- Python 3 + venv + зависимости
- API сервис (FastAPI на порту 8000)
- Telegram бот (aiogram)
- WebApp (доступна по /app)
- systemd сервисы с автозапуском

## Эндпоинты

| URL | Описание |
|-----|----------|
| `/sub` | Подписка; формат выбирается по `User-Agent` |
| `/sub/lte`, `/sub/wifi`, `/sub/3g`, `/sub/best` | Профили под тип сети |
| `/sub?format=clash\|singbox\|xray\|uri\|base64` | Принудительный формат |
| `/sub?protocol=vless,trojan` | Фильтр по протоколам (`vless,vmess,trojan,ss,hysteria2,tuic`) |
| `/sub?country=DE,NL` | Фильтр по странам |
| `/sub?alive=false` | Не отбрасывать непроверенные узлы |
| `/sub?ports=443,8443`, `/sub?max=30` | Фильтр по портам, лимит количества |
| `/stats` | Статистика пула: протоколы, страны, живость, источники |
| `/health` | Состояние проверок (живые/мёртвые, медиана задержки) |
| `/probe` | Живая проверка выборки узлов |
| `/app` | WebApp |
| `/refresh` | Обновить кэш (POST, `X-Refresh-Token` если задан `REFRESH_TOKEN`) |

Если живых узлов ещё нет (холодный старт), ответ `503` с `Retry-After: 30`.

## Как отбираются узлы

1. Источники → разбор всех схем → дедупликация.
2. Кандидаты (лучшие по оценке порта/транспорта) проверяются в фоне каждые `REFRESH_INTERVAL` секунд; результат кэшируется `HEALTH_TTL`.
3. В выдачу попадают только узлы, прошедшие проверку; порядок — по оценке и измеренной задержке.
4. Лимиты: не более `MAX_PER_HOST` узлов на хост, не более 40% одной страны, UDP-узлы (Hysteria2/TUIC)
   получают небольшую долю `UDP_SLOTS_PERCENT`: из этой среды они не проверяются, и подписка помечает их как непроверенные.
5. Xray 26+ убрал `allowInsecure`, поэтому узлы с невалидным сертификатом в Xray-формат не попадают (в Clash и sing-box остаются).

## Telegram бот

Команды:
- `/start` — главное меню с кнопками
- `/lte`, `/wifi`, `/3g` — подписка для сети (в сообщении — число проверенных живых узлов и ссылки на Clash / sing-box / Xray)
- `/best` — лучшие конфиги
- `/stats` — статистика (протоколы, страны, живость)
- `/admin` — управление (для админов)

## Переменные окружения

| Переменная | Описание |
|-----------|----------|
| `TELEGRAM_BOT_TOKEN` | Токен от @BotFather |
| `ADMIN_IDS` | Telegram ID админов (через запятую) |
| `PROXY_SUB_API` | URL API (default: http://127.0.0.1:8000) |
| `WEBAPP_URL` | URL WebApp для кнопки в боте |
| `PUBLIC_URL` | Публичный адрес сервиса (ссылки в боте, `profile-web-page-url`) |
| `PROFILE_TITLE`, `SUPPORT_URL`, `ANNOUNCE`, `PROFILE_UPDATE_INTERVAL` | Заголовки подписки |
| `SUB_TOTAL_BYTES`, `SUB_EXPIRE_DAYS`, `SUB_REFILL_TS` | Значения `subscription-userinfo` и `subscription-refill-date` |
| `EXTRA_SOURCES` | Дополнительные источники через запятую |
| `REFRESH_INTERVAL`, `HEALTH_TTL`, `HEALTH_TIMEOUT`, `HEALTH_CONCURRENCY`, `HEALTH_CANDIDATES`, `COLD_START_WAIT` | Параметры проверки живости |
| `MAX_PER_HOST`, `UDP_SLOTS_PERCENT` | Лимиты отбора |
| `REFRESH_TOKEN` | Защита `POST /refresh` |

## Тесты

```bash
pip install -e '.[dev]'
pytest
```

## Управление

```bash
# Статус
systemctl status proxy-sub-api proxy-sub-bot

# Логи
journalctl -u proxy-sub-api -f
journalctl -u proxy-sub-bot -f

# Перезапуск
systemctl restart proxy-sub-api proxy-sub-bot

# Обновление
cd /opt/proxy-sub/repo && git pull
systemctl restart proxy-sub-api proxy-sub-bot
```
