import asyncio
import os
import re
import unicodedata

import httpx


class GatewayError(Exception):
    pass


def phone_ok(value: str) -> bool:
    return bool(re.fullmatch(r"\+[1-9]\d{7,14}", value))


def sms_reply(analysis) -> str:
    def plain(value: str, width: int) -> str:
        value = unicodedata.normalize("NFKD", value.replace("\n", " ")).encode("ascii", "ignore").decode()
        return value.strip(" .")[:width].rstrip(" ,;.")
    return f"CyberShield: {analysis.risk_level} risk. {plain(analysis.reason, 45)}. {plain(analysis.safe_action, 58)}. No AI safety guarantee."[:160]


def send_sms(to: str, body: str) -> dict:
    if not phone_ok(to):
        raise GatewayError("Invalid international phone number")
    username, key = os.getenv("AT_USERNAME"), os.getenv("AT_API_KEY")
    if not username or not key:
        raise GatewayError("Africa's Talking is not configured")
    environment = os.getenv("AT_ENVIRONMENT", "sandbox")
    if environment not in {"sandbox", "production"} or (environment == "sandbox") != (username == "sandbox"):
        raise GatewayError("Africa's Talking environment and username do not match")
    import africastalking

    africastalking.initialize(username, key)
    sender = os.getenv("AT_SMS_SHORTCODE") or os.getenv("AT_SMS_SENDER_ID") or None
    try:
        result = africastalking.SMS.send(body, [to], sender_id=sender)
    except Exception as exc:
        raise GatewayError("SMS gateway request failed") from exc
    recipients = result.get("SMSMessageData", {}).get("Recipients", []) if isinstance(result, dict) else []
    recipient = recipients[0] if recipients else {}
    status = str(recipient.get("status", ""))
    if not recipient.get("messageId") or status.lower() not in {"success", "sent"}:
        raise GatewayError(f"SMS gateway did not accept message: {status or 'unknown'}")
    return {"message_id": str(recipient["messageId"]), "status": status}


async def send_sms_async(to: str, body: str) -> dict:
    return await asyncio.wait_for(asyncio.to_thread(send_sms, to, body), timeout=20)


async def send_whatsapp(to: str, body: str) -> str:
    token, phone_id = os.getenv("WHATSAPP_ACCESS_TOKEN"), os.getenv("WHATSAPP_PHONE_NUMBER_ID")
    if not token or not phone_id:
        raise GatewayError("WhatsApp is not configured")
    async with httpx.AsyncClient(timeout=httpx.Timeout(15.0, connect=5.0)) as client:
        response = await client.post(f"https://graph.facebook.com/v22.0/{phone_id}/messages", headers={"Authorization": f"Bearer {token}"}, json={"messaging_product": "whatsapp", "to": to, "type": "text", "text": {"body": body[:4096]}})
        response.raise_for_status()
    return response.json()["messages"][0]["id"]
