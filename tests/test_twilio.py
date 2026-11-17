from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from twilio.request_validator import RequestValidator

from fraud_lens.ai import ScamAnalysis
from fraud_lens.app import app
from fraud_lens.storage import event_status
from fraud_lens.twilio_whatsapp import status_callback_url

URL = "https://example.test/webhooks/twilio/whatsapp?source=sandbox"
PATH = "/webhooks/twilio/whatsapp?source=sandbox"
SENDER = "whatsapp:+15551234567"
USER = "whatsapp:+27821234567"
SID = "SM" + "a" * 32


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "twilio.db"))
    monkeypatch.setenv("TWILIO_ACCOUNT_SID", "AC" + "1" * 32)
    monkeypatch.setenv("TWILIO_AUTH_TOKEN", "test-auth-token")
    monkeypatch.setenv("TWILIO_WHATSAPP_FROM", SENDER)
    monkeypatch.setenv("TWILIO_WEBHOOK_URL", URL)
    return TestClient(app)


def signed_post(client, data, signature=None):
    signature = signature if signature is not None else RequestValidator("test-auth-token").compute_signature(URL, data)
    return client.post(PATH, data=data, headers={"X-Twilio-Signature": signature})


def payload(**changes):
    data = {"From": USER, "To": SENDER, "Body": "Your bank needs your PIN", "MessageSid": SID, "NumMedia": "0"}
    data.update(changes)
    return data


def test_valid_signed_webhook_and_shared_analysis(client, monkeypatch):
    sent = []
    async def analyze(message):
        assert message == "Your bank needs your PIN"
        return ScamAnalysis("HIGH", "Requests a PIN", ["Bank impersonation"], "Call your bank", "Keep PINs private")
    async def send(to, body):
        sent.append((to, body))
        return "SM" + "b" * 32, "queued"
    monkeypatch.setattr("fraud_lens.app.analyze_scam", analyze)
    monkeypatch.setattr("fraud_lens.app.send_twilio_whatsapp_async", send)
    response = signed_post(client, payload())
    assert response.status_code == 200
    assert response.text == "<Response/>"
    assert sent[0][0] == USER
    assert "Fraud Lens — HIGH" in sent[0][1]
    assert "What to do: Call your bank" in sent[0][1]
    assert "Cyber Tip: Keep PINs private" in sent[0][1]
    assert event_status("twilio_whatsapp", SID) == "gateway:queued"
    assert signed_post(client, payload()).status_code == 200
    assert len(sent) == 1


def test_plain_e164_config_accepts_real_twilio_to_and_sends_with_prefix(client, monkeypatch):
    monkeypatch.setenv("TWILIO_WHATSAPP_FROM", SENDER.removeprefix("whatsapp:"))
    seen = []
    async def analyze(message):
        seen.append(message)
        return ScamAnalysis("LOW", "No clear warning signs", [], "Verify independently", "Stay alert")
    async def send(to, body):
        seen.append((to, body))
        return "SM" + "b" * 32, "queued"
    monkeypatch.setattr("fraud_lens.app.analyze_scam", analyze)
    monkeypatch.setattr("fraud_lens.app.send_twilio_whatsapp_async", send)
    response = signed_post(client, payload(Body="Hi, this is a test"))
    assert response.status_code == 200
    assert seen[0] == "Hi, this is a test"
    assert seen[1][0] == USER


def test_invalid_signature_and_malformed_payload(client):
    assert signed_post(client, payload(), "bad").status_code == 403
    assert signed_post(client, payload(From="+27821234567")).status_code == 400
    assert signed_post(client, payload(MessageSid="bad")).status_code == 400
    assert signed_post(client, payload(NumMedia="x")).status_code == 400


@pytest.mark.parametrize("changes,expected", [({"Body": ""}, "Please send a suspicious text"), ({"NumMedia": "1", "Body": "caption"}, "Media analysis is not available")])
def test_empty_and_media_skip_analysis(client, monkeypatch, changes, expected):
    async def no_analysis(_):
        pytest.fail("Gemini should not receive this payload")
    replies = []
    async def send(_, body):
        replies.append(body)
        return "SM" + "b" * 32, "queued"
    monkeypatch.setattr("fraud_lens.app.analyze_scam", no_analysis)
    monkeypatch.setattr("fraud_lens.app.send_twilio_whatsapp_async", send)
    assert signed_post(client, payload(**changes)).status_code == 200
    assert expected in replies[0]


def test_gemini_failure_sends_notice(client, monkeypatch):
    async def failed(_):
        raise RuntimeError("Gemini unavailable")
    replies = []
    async def send(_, body):
        replies.append(body)
        return "SM" + "b" * 32, "queued"
    monkeypatch.setattr("fraud_lens.app.analyze_scam", failed)
    monkeypatch.setattr("fraud_lens.app.send_twilio_whatsapp_async", send)
    assert signed_post(client, payload()).status_code == 200
    assert "Analysis is unavailable" in replies[0]
    assert "HIGH" not in replies[0]


def test_twilio_api_failure_is_recorded(client, monkeypatch):
    async def analyze(_):
        return ScamAnalysis("LOW", "No clear warning", [], "Verify", "Stay alert")
    async def failed_send(*_):
        raise RuntimeError("Twilio unavailable")
    monkeypatch.setattr("fraud_lens.app.analyze_scam", analyze)
    monkeypatch.setattr("fraud_lens.app.send_twilio_whatsapp_async", failed_send)
    assert signed_post(client, payload()).status_code == 503
    assert event_status("twilio_whatsapp", SID) == "failed"


def test_outbound_sdk_uses_whatsapp_addresses(client, monkeypatch):
    from fraud_lens import twilio_whatsapp
    calls = []
    class FakeClient:
        def __init__(self, account, token, http_client):
            calls.append((account, token, http_client.timeout))
            self.messages = self
        def create(self, **kwargs):
            calls.append(kwargs)
            return SimpleNamespace(sid="SM" + "b" * 32, status="queued")
    monkeypatch.setattr(twilio_whatsapp, "Client", FakeClient)
    sid, status = twilio_whatsapp.send_twilio_whatsapp(USER, "Fraud Lens — HIGH")
    assert sid.startswith("SM") and status == "queued"
    assert calls[1] == {"from_": SENDER, "to": USER, "body": "Fraud Lens — HIGH", "status_callback": URL.replace("/whatsapp?", "/whatsapp/status?")}


def test_outbound_sdk_normalizes_plain_e164_sender(client, monkeypatch):
    from fraud_lens import twilio_whatsapp
    monkeypatch.setenv("TWILIO_WHATSAPP_FROM", SENDER.removeprefix("whatsapp:"))
    sent = []
    class FakeClient:
        def __init__(self, *_args, **_kwargs):
            self.messages = self
        def create(self, **kwargs):
            sent.append(kwargs)
            return SimpleNamespace(sid="SM" + "b" * 32, status="queued")
    monkeypatch.setattr(twilio_whatsapp, "Client", FakeClient)
    twilio_whatsapp.send_twilio_whatsapp(USER, "Test")
    assert sent[0]["from_"] == SENDER


def test_signed_delivery_status(client):
    data = {"MessageSid": "SM" + "b" * 32, "MessageStatus": "delivered"}
    signature = RequestValidator("test-auth-token").compute_signature(status_callback_url(), data)
    response = client.post("/webhooks/twilio/whatsapp/status?source=sandbox", data=data, headers={"X-Twilio-Signature": signature})
    assert response.status_code == 200
    assert event_status("twilio_delivery", data["MessageSid"]) == "delivered"
    assert client.post("/webhooks/twilio/whatsapp/status?source=sandbox", data=data, headers={"X-Twilio-Signature": "bad"}).status_code == 403
