import asyncio
import os
import re
from urllib.parse import urlsplit, urlunsplit

from twilio.http.http_client import TwilioHttpClient
from twilio.request_validator import RequestValidator
from twilio.rest import Client

from .ai import ScamAnalysis


def whatsapp_address(value: str) -> bool:
    return bool(re.fullmatch(r"whatsapp:\+[1-9]\d{7,14}", value))


def configured_whatsapp_sender() -> str:
    value = os.getenv("TWILIO_WHATSAPP_FROM", "")
    if re.fullmatch(r"\+[1-9]\d{7,14}", value):
        value = "whatsapp:" + value
    if not whatsapp_address(value):
        raise RuntimeError("Twilio WhatsApp sender is not configured")
    return value


def status_callback_url() -> str:
    parsed = urlsplit(os.getenv("TWILIO_WEBHOOK_URL", ""))
    if parsed.scheme != "https" or parsed.path != "/webhooks/twilio/whatsapp" or parsed.fragment:
        raise RuntimeError("Twilio webhook URL is not configured")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path + "/status", parsed.query, ""))


def validate_twilio_signature(form: dict[str, str], signature: str, *, status_callback: bool = False) -> bool:
    token = os.getenv("TWILIO_AUTH_TOKEN")
    url = os.getenv("TWILIO_WEBHOOK_URL", "")
    parsed = urlsplit(url)
    if not token or parsed.scheme != "https" or parsed.path != "/webhooks/twilio/whatsapp" or parsed.fragment:
        raise RuntimeError("Twilio webhook verification is not configured")
    canonical_url = status_callback_url() if status_callback else url
    return RequestValidator(token).validate(canonical_url, form, signature)


def format_analysis(analysis: ScamAnalysis) -> str:
    if analysis.risk_level == "UNKNOWN":
        return "Fraud Lens: I couldn't reliably assess this message. Don't open links or share codes. Verify through an official channel."
    return (
        f"Fraud Lens — {analysis.risk_level}\n\n"
        f"{analysis.reason[:180]}\n\n"
        f"What to do: {analysis.safe_action[:180]}\n\n"
        f"Cyber Tip: {analysis.tip[:140]}\n\n"
        "AI cannot guarantee safety."
    )


def send_twilio_whatsapp(to: str, body: str) -> tuple[str, str]:
    account = os.getenv("TWILIO_ACCOUNT_SID")
    token = os.getenv("TWILIO_AUTH_TOKEN")
    if not account or not token:
        raise RuntimeError("Twilio WhatsApp sending is not configured")
    sender = configured_whatsapp_sender()
    if not whatsapp_address(to):
        raise ValueError("Invalid WhatsApp recipient")
    client = Client(account, token, http_client=TwilioHttpClient(timeout=5))
    message = client.messages.create(from_=sender, to=to, body=body[:1500], status_callback=status_callback_url())
    if not message.sid:
        raise RuntimeError("Twilio did not return a message SID")
    return message.sid, str(message.status or "accepted")


async def send_twilio_whatsapp_async(to: str, body: str) -> tuple[str, str]:
    return await asyncio.wait_for(asyncio.to_thread(send_twilio_whatsapp, to, body), timeout=6)
