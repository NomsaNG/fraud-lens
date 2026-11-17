# Fraud lens / CyberShield Africa

Mobile-first scam education with one AI analysis service behind web, SMS and WhatsApp. USSD uses short rule-based guidance and a three-question quiz. Twilio WhatsApp was reported tested end to end through ngrok; the Render deployment and its public callbacks still need verification.

## Run locally on macOS with VS Code

Install Python 3.13 and open this folder in VS Code. In its terminal:

```sh
python3.13 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Fill `.env` with your own credentials. Keep it private. Start the app with:

```sh
uvicorn fraud_lens.app:app --reload --host 127.0.0.1 --port 8000 --no-access-log
```

Open `http://127.0.0.1:8000`. Run the automated checks with `python -m pytest -q` after installing `pytest`. `/health` reports **configuration**, not successful provider delivery. Set `GEMINI_API_KEY` for AI analysis and chat; `GEMINI_MODEL` defaults to `gemini-3.5-flash-lite`. The older `gemini-2.5-flash-lite` is unavailable to some new keys, so update an existing `.env` model value if Gemini returns 404. Without a key, AI routes return a clear 503. If analysis fails after a request, the result is explicitly `UNKNOWN`. The UI never claims to monitor private messages automatically.

## Africa's Talking sandbox SMS

1. Create an [Africa's Talking sandbox account](https://developers.africastalking.com/) and copy its API key. Set `AT_USERNAME=sandbox`, `AT_ENVIRONMENT=sandbox`, and `AT_API_KEY` in `.env`.
2. In the sandbox dashboard, configure the available **two-way SMS shortcode** and set `AT_SMS_SHORTCODE` to that code. An alphanumeric sender ID alone cannot receive replies. Set `AT_SMS_SENDER_ID` only if separately provisioned; the app prefers the shortcode for replies.
3. Generate a long random `AT_WEBHOOK_SECRET`. Configure the incoming SMS callback as `https://YOUR_HOST/webhooks/africastalking/sms?secret=YOUR_SECRET` and the delivery callback as `https://YOUR_HOST/webhooks/africastalking/sms/delivery?secret=YOUR_SECRET`. Use HTTPS. Treat these URLs as credentials because Africa's Talking does not supply a signature scheme used by this app. Avoid logging query strings at your proxy.
4. For local testing, run `ngrok http 8000`, then use its HTTPS URL as `YOUR_HOST`. Keep the app and ngrok running.
5. In Africa's Talking's browser phone simulator, send a suspicious text to the sandbox shortcode. Confirm the callback reached the app, the official SDK returned a `Success`/message ID, and the simulated phone received a reply. Check the delivery callback separately. Sandbox integration uses the real provider API and simulator; it does **not** deliver to a physical phone.

Inbound callback fields used: `from`, `to`, `text`, and `id` (or `messageId`). Duplicate inbound IDs are claimed before analysis. Only minimal IDs, gateway status and timestamps are stored; raw message text is not retained. A gateway `Success` means accepted for sending, **not handset delivery**.

## Africa's Talking sandbox USSD

Create a sandbox USSD channel in the dashboard and set `AT_USSD_SERVICE_CODE` to its assigned code. Set its callback URL to `https://YOUR_HOST/webhooks/africastalking/ussd?secret=YOUR_SECRET`. Dial that code in the official browser simulator. Navigate all five menus, complete the quiz, and request the one-time SMS tip. Verify that the gateway accepted the tip and it appears in the simulator. USSD receives cumulative `text`; the backend returns `CON` or `END` plain text and makes no LLM call during the session.

## WhatsApp

Configure a Meta WhatsApp Cloud API app, webhook subscription, access token, phone number ID, verify token and app secret in `.env`. Use `GET/POST https://YOUR_HOST/webhooks/whatsapp`. The GET route echoes Meta's challenge only for the configured token; POST validates `X-Hub-Signature-256` over the raw body. Subscribe to message events and test with an explicitly sent text. This channel remains **unverified** until a real Meta webhook and reply have succeeded.

### Twilio WhatsApp (separate provider)

1. In the [Twilio Console](https://www.twilio.com/console), obtain the Account SID and Auth Token. Set `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, and `TWILIO_WHATSAPP_FROM` in `.env`. The sender must include `whatsapp:` and the exact Twilio test or approved sender number.
2. Activate WhatsApp in [Twilio's testing flow](https://www.twilio.com/docs/whatsapp/quickstart). Join from your personal WhatsApp using the displayed QR code or `join` phrase. Legacy Sandbox and newer trial accounts have different restrictions: the legacy Sandbox permits free-form replies inside the 24-hour customer-service window, while the newer trial flow may require Twilio-provided templates for REST messages and may not support direct TwiML replies. Check the account's Console mode before expecting dynamic Gemini replies.
3. Run the app locally and `ngrok http 8000` on macOS, or use an existing public HTTPS deployment. Set `TWILIO_WEBHOOK_URL` in `.env` to the **exact** external URL, for example `https://PUBLIC_HOST/webhooks/twilio/whatsapp`. Include any query string exactly as entered in Twilio. Restart FastAPI after editing `.env`.
4. In Twilio's incoming-message configuration, set that same URL and method `POST`. Do not turn off signature validation for local testing. The app uses Twilio's official `RequestValidator` and the configured public URL, which avoids local HTTP/proxy scheme mismatches.
5. Send a suspicious **text** from the joined WhatsApp number. Confirm the webhook arrives, Gemini returns a risk assessment, the Twilio REST API accepts the reply, and the reply arrives in WhatsApp. The app does not process media. It uses the existing event store to prevent duplicate replies by inbound `MessageSid` and records the outbound SID and gateway status. It also requests delivery updates at the derived `/webhooks/twilio/whatsapp/status` URL, protected by Twilio signatures; check Twilio message logs for errors.

If Twilio returns 403 at the webhook, check `TWILIO_AUTH_TOKEN` and that `TWILIO_WEBHOOK_URL` exactly matches the Console URL, including HTTPS and query string. If the webhook succeeds but outbound fails, check the sender's `whatsapp:` prefix, joined recipient, 24-hour window, trial restrictions, and Twilio error code. The app sends a short failure notice when Gemini cannot assess a message. A gateway `queued` status does not prove WhatsApp delivery. The local SQLite event store remains ephemeral on Cloud Run as described below.

## Render free Web Service

Push this project to a GitHub repository without `.env` or `.venv`. Create a Render **Web Service** from that repository (or deploy its `render.yaml` Blueprint): runtime **Python**, instance **Free**, build `pip install -r requirements.txt`, start `uvicorn fraud_lens.app:app --host 0.0.0.0 --port $PORT --no-access-log`, health check `/health`. The root `.python-version` selects Python 3.13. Set secrets in Render's **Environment** settings, never in GitHub or `render.yaml`: `GEMINI_API_KEY`, `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_WHATSAPP_FROM`, and any Africa's Talking credentials in `.env.example`. Set `GEMINI_MODEL=gemini-3.5-flash-lite` (already in the Blueprint). Do not copy the local `TWILIO_WEBHOOK_URL` if it points to ngrok.

After Render shows the **actual** HTTPS URL, set `TWILIO_WEBHOOK_URL=https://ACTUAL-RENDER-HOST/webhooks/twilio/whatsapp` in Render, then set that exact URL as the Twilio WhatsApp incoming webhook with method **POST**. If you use a query string, copy it exactly in both places. The app derives its signed delivery callback at `https://ACTUAL-RENDER-HOST/webhooks/twilio/whatsapp/status`; Twilio sends delivery updates there when requested by the sender. Set `PUBLIC_BASE_URL` to the actual HTTPS origin if you use it in operations.

The Africa's Talking callback URLs are `https://ACTUAL-RENDER-HOST/webhooks/africastalking/sms?secret=YOUR_AT_WEBHOOK_SECRET`, `https://ACTUAL-RENDER-HOST/webhooks/africastalking/sms/delivery?secret=YOUR_AT_WEBHOOK_SECRET`, and `https://ACTUAL-RENDER-HOST/webhooks/africastalking/ussd?secret=YOUR_AT_WEBHOOK_SECRET`. Configure these in the Africa's Talking dashboard only after setting the same secret in Render.

Verify the public homepage, `/health`, `/static/app.js`, one Gemini analysis, and a genuine inbound/outbound WhatsApp exchange. Check Twilio delivery status and errors separately. [Render Free services spin down after 15 minutes of inactivity](https://render.com/docs/free); wake-up can take about a minute, delaying or timing out a provider webhook. The free filesystem is ephemeral, so the app's local SQLite deduplication and delivery metadata can disappear on restart, redeploy, or spin-down. Do not rely on it for paid production messaging without durable persistence. No artificial keep-alive is configured.

## Cloud Run

Google Cloud [supports `africa-south1`](https://docs.cloud.google.com/run/docs/locations). Source deployment uses [Cloud Build buildpacks](https://docs.cloud.google.com/run/docs/deploying-source-code), so no Dockerfile is needed. After authenticating `gcloud`, selecting a project, enabling Cloud Run, Cloud Build and Artifact Registry, and configuring secrets through Secret Manager, deploy for example:

```sh
gcloud run deploy fraud-lens --source . --region africa-south1 --allow-unauthenticated --max-instances 1
```

The `Procfile` starts Uvicorn on port 8080. Bind sensitive environment variables through Cloud Run Secret Manager rather than copying `.env` into the service. Set `PUBLIC_BASE_URL` to the resulting HTTPS URL, then configure provider callback URLs and test them. Cloud Run's local filesystem is ephemeral: this prototype's SQLite duplicate and delivery tracking is suitable for local/single-instance testing but **not durable across Cloud Run restarts**. Before handling paid production traffic, replace that store with durable shared persistence and use a shared rate limiter. Multi-instance production traffic must not rely on the current in-memory rate limit or local SQLite file.

For live Africa's Talking service, provision and approve the real two-way shortcode and USSD code, change `AT_ENVIRONMENT=production`, and replace sandbox credentials and numbers with live ones. Repeat provider callback and delivery tests. WhatsApp requires separate live Meta or Twilio credentials and webhook configuration.

## Verification status

| Flow | Status here |
| --- | --- |
| Web and API routes | Local automated tests passed; a live Gemini analysis succeeded locally |
| SMS callback, SDK adapter, deduplication, delivery handler | Local tests passed; Africa's Talking sandbox traffic unverified |
| USSD menus and one-time tip | Local tests passed; Africa's Talking sandbox traffic unverified |
| WhatsApp signature and payload route | Local tests passed; Meta traffic unverified |
| Twilio WhatsApp signature, shared analysis, sender and delivery callbacks | Local tests passed; user-reported ngrok flow succeeded; Render flow unverified |
| Cloud Run HTTPS deployment | Not deployed |
| Render HTTPS deployment | Not deployed |

Never mark SMS or USSD complete from local callback tests alone. Reconcile failed or timed-out gateway requests manually before replaying them, since the gateway may have accepted a request despite a local timeout.
