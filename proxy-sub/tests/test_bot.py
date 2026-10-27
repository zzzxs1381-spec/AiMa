import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def test_bot_imports_without_token_and_helpers(monkeypatch):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    import bot

    assert bot.parse_admin_ids("1, 2,,x") == {1, 2}
    assert not bot.is_public_url("http://127.0.0.1:8000/sub/lte")
    assert not bot.is_public_url("http://localhost/sub")
    assert bot.is_public_url("https://sub.example.com/sub/lte")


def test_bot_stats_extra_and_format_links(monkeypatch):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    import bot

    monkeypatch.setattr(bot, "PUBLIC_URL", "https://sub.example.com")

    text = bot.stats_extra({"health": {"alive": 40, "dead": 5, "latency_ms_median": 123.4},
                            "by_protocol": {"vless": 10, "trojan": 20}, "by_country": {"DE": 7, "US": 3}})
    assert "40" in text and "123.4" in text and text.index("trojan") < text.index("vless")
    assert "DE 7" in text
    assert bot.stats_extra({}) == ""
    kb = bot.sub_link_keyboard("lte")
    urls = [b.url for row in kb.inline_keyboard for b in row if b.url]
    assert any(u.endswith("/sub/lte?format=clash") for u in urls)
    assert any(u.endswith("?format=singbox") for u in urls) and any(u.endswith("?format=xray") for u in urls)
