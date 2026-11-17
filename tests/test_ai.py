import asyncio
import json
from types import SimpleNamespace

import pytest

from fraud_lens import ai


def test_structured_analysis_and_chat(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    seen = []

    async def fake_generate(contents, config):
        seen.append((contents, config))
        if config.response_mime_type == "application/json":
            return SimpleNamespace(text=json.dumps({"risk_level": "HIGH", "reason": "Requests an OTP", "indicators": ["Urgency"], "safe_action": "Contact your bank directly", "tip": "Never share codes"}))
        return SimpleNamespace(text="Keep your OTP private.")

    monkeypatch.setattr(ai, "_generate", fake_generate)
    result = asyncio.run(ai.analyze_scam("Send your OTP"))
    assert result.risk_level == "HIGH"
    assert result.safe_action == "Contact your bank directly"
    assert set(seen[0][1].response_json_schema["properties"]) == {"risk_level", "reason", "indicators", "safe_action", "tip"}
    assert asyncio.run(ai.answer_question("What is an OTP?")) == "Keep your OTP private."


def test_failed_analysis_is_unknown(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    async def broken(*_):
        raise TimeoutError("provider unavailable")
    monkeypatch.setattr(ai, "_generate", broken)
    result = asyncio.run(ai.analyze_scam("Check this message"))
    assert result.risk_level == "UNKNOWN"
    assert result.indicators == []
    assert "unavailable" in result.reason


def test_missing_key_is_error(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="not configured"):
        asyncio.run(ai.analyze_scam("Check this message"))


def test_sdk_async_call_uses_configured_model(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setenv("GEMINI_MODEL", "gemini-3.5-flash-lite")
    seen = []

    class AsyncClient:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *_):
            pass
        @property
        def models(self):
            return self
        async def generate_content(self, **kwargs):
            seen.append(kwargs)
            return SimpleNamespace(text="ok")

    monkeypatch.setattr(ai.genai, "Client", lambda **kwargs: SimpleNamespace(aio=AsyncClient()))
    asyncio.run(ai._generate("question", ai.types.GenerateContentConfig(max_output_tokens=10)))
    assert seen[0]["model"] == "gemini-3.5-flash-lite"
    assert seen[0]["contents"] == "question"
