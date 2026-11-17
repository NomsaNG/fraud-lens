import asyncio
import hashlib
import hmac
import json
import os
import re
import time
from collections import defaultdict, deque
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .ai import analyze_scam, answer_question
from .content import LESSONS, SAFETY_TIP
from .gateway import GatewayError, phone_ok, send_sms_async, send_whatsapp, sms_reply
from .storage import claim, delivery, event_status, mark
from .twilio_whatsapp import configured_whatsapp_sender, format_analysis, send_twilio_whatsapp_async, validate_twilio_signature, whatsapp_address
from .ussd import handle_ussd

load_dotenv()
app = FastAPI(title="Fraud lens", docs_url=None, redoc_url=None)
STATIC = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=STATIC), name="static")
hits: dict[str, deque] = defaultdict(deque)


class TextInput(BaseModel):
    message: str = Field(min_length=3, max_length=4000)


def limit(key: str, count: int = 20, window: int = 60) -> None:
    now = time.monotonic()
    bucket = hits[key]
    while bucket and bucket[0] < now - window:
        bucket.popleft()
    if len(bucket) >= count:
        raise HTTPException(429, "Too many requests. Try again shortly.")
    bucket.append(now)


async def form_payload(request: Request) -> dict[str, str]:
    if int(request.headers.get("content-length", "0") or "0") > 8192:
        raise HTTPException(413, "Request too large")
    if not request.headers.get("content-type", "").startswith("application/x-www-form-urlencoded"):
        raise HTTPException(415, "Expected form-encoded data")
    raw = await request.body()
    if len(raw) > 8192:
        raise HTTPException(413, "Request too large")
    from urllib.parse import parse_qs
    try:
        return {key: values[-1] for key, values in parse_qs(raw.decode("utf-8"), keep_blank_values=True, strict_parsing=True).items()}
    except (UnicodeDecodeError, ValueError):
        raise HTTPException(400, "Malformed form")


def check_at_secret(request: Request) -> None:
    secret = os.getenv("AT_WEBHOOK_SECRET")
    if not secret:
        raise HTTPException(503, "Webhook secret is not configured")
    supplied = request.query_params.get("secret", "")
    if not hmac.compare_digest(supplied, secret):
        raise HTTPException(403, "Invalid webhook secret")


@app.get("/")
def home():
    return FileResponse(STATIC / "index.html")


@app.get("/health")
def health():
    meta_ready = bool(os.getenv("WHATSAPP_ACCESS_TOKEN") and os.getenv("WHATSAPP_PHONE_NUMBER_ID") and os.getenv("WHATSAPP_APP_SECRET"))
    twilio_ready = bool(os.getenv("TWILIO_ACCOUNT_SID") and os.getenv("TWILIO_AUTH_TOKEN") and os.getenv("TWILIO_WHATSAPP_FROM") and os.getenv("TWILIO_WEBHOOK_URL"))
    return {"status": "ok", "ai_configured": bool(os.getenv("GEMINI_API_KEY")), "sms_configured": bool(os.getenv("AT_API_KEY") and os.getenv("AT_USERNAME") and os.getenv("AT_SMS_SHORTCODE")), "ussd_configured": bool(os.getenv("AT_USSD_SERVICE_CODE") and os.getenv("AT_WEBHOOK_SECRET")), "whatsapp_configured": meta_ready or twilio_ready, "twilio_whatsapp_configured": twilio_ready}


@app.get("/api/config")
def public_config():
    return {"environment": os.getenv("AT_ENVIRONMENT", "sandbox"), "sms_shortcode": os.getenv("AT_SMS_SHORTCODE", ""), "ussd_code": os.getenv("AT_USSD_SERVICE_CODE", ""), "whatsapp_available": bool((os.getenv("WHATSAPP_ACCESS_TOKEN") and os.getenv("WHATSAPP_PHONE_NUMBER_ID")) or (os.getenv("TWILIO_ACCOUNT_SID") and os.getenv("TWILIO_AUTH_TOKEN") and os.getenv("TWILIO_WHATSAPP_FROM") and os.getenv("TWILIO_WEBHOOK_URL")))}


@app.post("/api/analyze")
async def analyze(data: TextInput, request: Request):
    limit("web:" + (request.client.host if request.client else "unknown"))
    try:
        return await analyze_scam(data.message)
    except Exception:
        raise HTTPException(503, "Analysis is temporarily unavailable")


@app.post("/api/chat")
async def chat(data: TextInput, request: Request):
    limit("chat:" + (request.client.host if request.client else "unknown"))
    try:
        return {"answer": await answer_question(data.message)}
    except Exception:
        raise HTTPException(503, "Assistant is temporarily unavailable")


@app.get("/api/lessons")
def lessons():
    return LESSONS


@app.post("/webhooks/africastalking/sms")
async def inbound_sms(request: Request):
    check_at_secret(request)
    form = await form_payload(request)
    sender, body = form.get("from", ""), form.get("text", "")
    recipient = form.get("to", "")
    if not phone_ok(sender) or not 3 <= len(body) <= 4000 or (os.getenv("AT_SMS_SHORTCODE") and recipient != os.getenv("AT_SMS_SHORTCODE")):
        raise HTTPException(400, "Invalid SMS callback")
    event_id = form.get("id") or form.get("messageId")
    if not event_id or len(event_id) > 128:
        raise HTTPException(400, "Missing SMS message ID")
    if not claim("sms", event_id):
        return {"status": "duplicate", "previous_status": event_status("sms", event_id)}
    try:
        limit("sms:" + sender, 5, 3600)
        analysis = await analyze_scam(body)
        sent = await send_sms_async(sender, sms_reply(analysis))
        mark("sms", event_id, "gateway_accepted", sent["message_id"])
    except Exception:
        mark("sms", event_id, "failed")
        raise HTTPException(503, "SMS processing failed")
    return {"status": "gateway_accepted"}


@app.post("/webhooks/africastalking/sms/delivery")
async def sms_delivery(request: Request):
    check_at_secret(request)
    form = await form_payload(request)
    message_id = form.get("id") or form.get("messageId", "")
    status = form.get("status", "")
    if not message_id or len(message_id) > 128 or not status or len(status) > 80:
        raise HTTPException(400, "Invalid delivery report")
    delivery(message_id, status)
    return {"status": "recorded"}


@app.post("/webhooks/africastalking/ussd", response_class=PlainTextResponse)
async def ussd(request: Request):
    check_at_secret(request)
    form = await form_payload(request)
    session, phone, code, text = (form.get(k, "") for k in ("sessionId", "phoneNumber", "serviceCode", "text"))
    if not session or len(session) > 128 or not phone_ok(phone) or not code or (os.getenv("AT_USSD_SERVICE_CODE") and code != os.getenv("AT_USSD_SERVICE_CODE")):
        return PlainTextResponse("END Invalid session.")
    try:
        limit("ussd:" + phone, 40, 3600)
    except HTTPException:
        return PlainTextResponse("END Too many requests. Try later.")
    response, tip_due = handle_ussd(text)
    if tip_due:
        event_id = hashlib.sha256((session + ":tip").encode()).hexdigest()
        if claim("ussd_tip", event_id):
            try:
                sent = await send_sms_async(phone, SAFETY_TIP)
                mark("ussd_tip", event_id, "gateway_accepted", sent["message_id"])
            except Exception:
                mark("ussd_tip", event_id, "failed")
                response = "END We could not send the tip right now. Please try later."
        elif event_status("ussd_tip", event_id) == "failed":
            response = "END The tip could not be sent. Please try a new session later."
    return PlainTextResponse(response)


@app.get("/webhooks/whatsapp", response_class=PlainTextResponse)
def whatsapp_verify(request: Request):
    token = os.getenv("WHATSAPP_VERIFY_TOKEN")
    supplied = request.query_params.get("hub.verify_token", "")
    if token and request.query_params.get("hub.mode") == "subscribe" and hmac.compare_digest(token, supplied):
        return PlainTextResponse(request.query_params.get("hub.challenge", ""))
    raise HTTPException(403, "Verification failed")


@app.post("/webhooks/whatsapp")
async def whatsapp_inbound(request: Request):
    secret = os.getenv("WHATSAPP_APP_SECRET")
    if not secret:
        raise HTTPException(503, "WhatsApp is not configured")
    raw = await request.body()
    if len(raw) > 65536:
        raise HTTPException(413, "Request too large")
    signature = request.headers.get("x-hub-signature-256", "")
    expected = "sha256=" + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise HTTPException(403, "Invalid signature")
    try:
        payload = json.loads(raw)
        messages = [m for e in payload.get("entry", []) for c in e.get("changes", []) for m in c.get("value", {}).get("messages", [])]
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(400, "Invalid payload")
    for message in messages:
        if message.get("type") != "text":
            continue
        sender, event_id = message.get("from", ""), message.get("id", "")
        body = message.get("text", {}).get("body", "")
        if not re.fullmatch(r"[1-9]\d{7,14}", sender) or not event_id or not 3 <= len(body) <= 4000:
            continue
        limit("whatsapp:" + sender, 10, 3600)
        if not claim("whatsapp", event_id):
            continue
        try:
            analysis = await analyze_scam(body)
            outgoing_id = await send_whatsapp(sender, sms_reply(analysis))
            mark("whatsapp", event_id, "gateway_accepted", outgoing_id)
        except Exception:
            mark("whatsapp", event_id, "failed")
            raise HTTPException(503, "WhatsApp processing failed")
    return {"status": "ok"}


@app.post("/webhooks/twilio/whatsapp")
async def twilio_whatsapp_inbound(request: Request):
    form = await form_payload(request)
    try:
        valid = validate_twilio_signature(form, request.headers.get("x-twilio-signature", ""))
    except RuntimeError:
        raise HTTPException(503, "Twilio webhook is not configured")
    if not valid:
        raise HTTPException(403, "Invalid Twilio signature")

    sender, recipient = form.get("From", ""), form.get("To", "")
    event_id, body, media = form.get("MessageSid", ""), form.get("Body", ""), form.get("NumMedia", "")
    try:
        expected_recipient = configured_whatsapp_sender()
    except RuntimeError:
        raise HTTPException(503, "Twilio WhatsApp sender is not configured")
    if (not whatsapp_address(sender) or recipient != expected_recipient
            or not re.fullmatch(r"(?:SM|MM)[0-9a-fA-F]{32}", event_id)
            or not media.isdigit() or int(media) > 10 or len(body) > 4000):
        raise HTTPException(400, "Invalid Twilio WhatsApp callback")
    if not claim("twilio_whatsapp", event_id):
        return Response("<Response/>", media_type="application/xml")
    try:
        limit("twilio_whatsapp:" + sender, 10, 3600)
        if int(media):
            reply = "Fraud Lens: Please send text only. Media analysis is not available yet."
        elif not body.strip():
            reply = "Fraud Lens: Please send a suspicious text message to check. Do not include PINs or OTPs."
        else:
            try:
                analysis = await asyncio.wait_for(analyze_scam(body), timeout=8)
                reply = format_analysis(analysis)
            except Exception:
                reply = "Fraud Lens: Analysis is unavailable right now. Do not open links or share codes. Verify independently."
        outgoing_id, gateway_status = await send_twilio_whatsapp_async(sender, reply)
        mark("twilio_whatsapp", event_id, "gateway:" + gateway_status[:40], outgoing_id)
    except Exception:
        mark("twilio_whatsapp", event_id, "failed")
        raise HTTPException(503, "Twilio WhatsApp processing failed")
    return Response("<Response/>", media_type="application/xml")


@app.post("/webhooks/twilio/whatsapp/status")
async def twilio_whatsapp_status(request: Request):
    form = await form_payload(request)
    try:
        valid = validate_twilio_signature(form, request.headers.get("x-twilio-signature", ""), status_callback=True)
    except RuntimeError:
        raise HTTPException(503, "Twilio webhook is not configured")
    if not valid:
        raise HTTPException(403, "Invalid Twilio signature")
    sid, status = form.get("MessageSid", ""), form.get("MessageStatus", "")
    error_code = form.get("ErrorCode", "")
    if not re.fullmatch(r"(?:SM|MM)[0-9a-fA-F]{32}", sid) or status not in {"accepted", "queued", "sending", "sent", "delivered", "read", "undelivered", "failed"} or (error_code and not re.fullmatch(r"\d{1,10}", error_code)):
        raise HTTPException(400, "Invalid Twilio delivery callback")
    claim("twilio_delivery", sid)
    detail = status + (":" + error_code if error_code else "")
    mark("twilio_delivery", sid, detail)
    delivery(sid, detail)
    return Response("<Response/>", media_type="application/xml")
