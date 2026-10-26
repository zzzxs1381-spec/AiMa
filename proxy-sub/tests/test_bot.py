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
