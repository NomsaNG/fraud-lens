import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient

from fraud_lens.ai import ScamAnalysis
from fraud_lens.app import app
from fraud_lens.ussd import handle_ussd


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("AT_WEBHOOK_SECRET", "test-secret")
    monkeypatch.setenv("AT_SMS_SHORTCODE", "12345")
    monkeypatch.setenv("AT_USSD_SERVICE_CODE", "*384*123#")
    return TestClient(app)


def test_health_and_lessons(client):
    assert client.get("/health").status_code == 200
    assert len(client.get("/api/lessons").json()) >= 4
    assert client.get("/").status_code == 200


def test_missing_gemini_key_is_safe_error(client, monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    assert client.get("/health").json()["ai_configured"] is False
    response = client.post("/api/analyze", json={"message": "Please check this text"})
    assert response.status_code == 503
    assert response.json()["detail"] == "Analysis is temporarily unavailable"


def test_web_analysis(client, monkeypatch):
    async def fake(_):
        return ScamAnalysis("HIGH", "Asks for your PIN", ["Urgency"], "Call your bank", "Do not share codes")
    monkeypatch.setattr("fraud_lens.app.analyze_scam", fake)
    r = client.post("/api/analyze", json={"message": "Send me your PIN now"})
    assert r.json()["risk_level"] == "HIGH"
    assert client.post("/api/analyze", json={"message": "x"}).status_code == 422


@pytest.mark.parametrize("path,expected", [("", "CON"), ("1", "CON"), ("1*1", "END Phishing"), ("1*2", "END Fake jobs"), ("1*3", "END Impostors"), ("1*4", "END Shopping"), ("2", "END Banks"), ("3", "CON"), ("3*1", "END"), ("3*2", "END"), ("3*3", "END"), ("4", "CON Q1"), ("4*2", "CON Q2"), ("4*2*1", "CON Q3"), ("4*2*1*2", "END Score: 3/3"), ("5", "CON"), ("5*2", "END No SMS"), ("9", "END Invalid")])
def test_menu_paths(path, expected):
    assert handle_ussd(path)[0].startswith(expected)


def test_sms_callback_and_duplicate(client, monkeypatch):
    calls = []
    async def fake_analyze(_):
        return ScamAnalysis("HIGH", "Phishing link", ["Link"], "Contact your bank directly", "Protect your PIN")
    async def fake_send(to, body):
        calls.append((to, body))
        return {"message_id": "gw1", "status": "Success"}
    monkeypatch.setattr("fraud_lens.app.analyze_scam", fake_analyze)
    monkeypatch.setattr("fraud_lens.app.send_sms_async", fake_send)
    data = {"from": "+27821234567", "to": "12345", "text": "Click the link now", "id": "in1"}
    url = "/webhooks/africastalking/sms?secret=test-secret"
    assert client.post(url, data=data).json()["status"] == "gateway_accepted"
    assert client.post(url, data=data).json()["status"] == "duplicate"
    assert len(calls) == 1
    assert client.post("/webhooks/africastalking/sms?secret=bad", data=data).status_code == 403
    assert client.post(url, data={"from": "bad"}).status_code == 400
    assert client.post("/webhooks/africastalking/sms/delivery?secret=test-secret", data={"id": "gw1", "status": "Delivered"}).status_code == 200


def test_ussd_tip_sent_once(client, monkeypatch):
    calls = []
    async def fake_send(to, body):
        calls.append(to)
        return {"message_id": "tip1", "status": "Success"}
    monkeypatch.setattr("fraud_lens.app.send_sms_async", fake_send)
    data = {"sessionId": "s1", "serviceCode": "*384*123#", "phoneNumber": "+27821234567", "text": "5*1"}
    url = "/webhooks/africastalking/ussd?secret=test-secret"
    assert client.post(url, data=data).text.startswith("END")
    assert client.post(url, data=data).text.startswith("END")
    assert len(calls) == 1


def test_whatsapp_signature(client, monkeypatch):
    monkeypatch.setenv("WHATSAPP_APP_SECRET", "app-secret")
    body = json.dumps({"entry": []}).encode()
    signature = "sha256=" + hmac.new(b"app-secret", body, hashlib.sha256).hexdigest()
    assert client.post("/webhooks/whatsapp", content=body, headers={"x-hub-signature-256": signature}).status_code == 200
    assert client.post("/webhooks/whatsapp", content=body).status_code == 403


def test_whatsapp_uses_shared_analysis(client, monkeypatch):
    monkeypatch.setenv("WHATSAPP_APP_SECRET", "app-secret")
    seen = []
    async def fake_analyze(message):
        seen.append(message)
        return ScamAnalysis("HIGH", "Fake bank link", ["Link"], "Contact your bank", "Never share a PIN")
    async def fake_send(to, body):
        seen.append((to, body))
        return "wa-out-1"
    monkeypatch.setattr("fraud_lens.app.analyze_scam", fake_analyze)
    monkeypatch.setattr("fraud_lens.app.send_whatsapp", fake_send)
    body = json.dumps({"entry": [{"changes": [{"value": {"messages": [{"id": "wa-in-1", "from": "27821234567", "type": "text", "text": {"body": "Check this bank link"}}]}}]}]}).encode()
    signature = "sha256=" + hmac.new(b"app-secret", body, hashlib.sha256).hexdigest()
    assert client.post("/webhooks/whatsapp", content=body, headers={"x-hub-signature-256": signature}).json()["status"] == "ok"
    assert seen[0] == "Check this bank link"
    assert "HIGH risk" in seen[1][1]


def test_sms_uses_official_sdk_interface(monkeypatch):
    import sys
    from types import SimpleNamespace
    from fraud_lens.gateway import send_sms, GatewayError
    calls = []
    sdk = SimpleNamespace(initialize=lambda u, k: calls.append((u, k)), SMS=SimpleNamespace(send=lambda body, recipients, sender_id: (calls.append((body, recipients, sender_id)) or {"SMSMessageData": {"Recipients": [{"status": "Success", "messageId": "gw2"}]}})))
    monkeypatch.setitem(sys.modules, "africastalking", sdk)
    monkeypatch.setenv("AT_USERNAME", "sandbox")
    monkeypatch.setenv("AT_API_KEY", "test-key")
    monkeypatch.setenv("AT_ENVIRONMENT", "sandbox")
    monkeypatch.setenv("AT_SMS_SHORTCODE", "12345")
    assert send_sms("+27821234567", "Test")["message_id"] == "gw2"
    assert calls == [("sandbox", "test-key"), ("Test", ["+27821234567"], "12345")]
    monkeypatch.delenv("AT_API_KEY")
    with pytest.raises(GatewayError):
        send_sms("+27821234567", "Test")
