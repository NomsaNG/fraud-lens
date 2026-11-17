
# 🛡️ Fraud Lens
### Learn. Check. Stay Scam-Safe.

**Fraud Lens** is an AI-powered cybersecurity education and scam-detection platform designed to help Africans identify suspicious messages, understand fraud risks, and protect themselves from cybercrime.

🌐 **Live Demo:** https://fraud-lens-0uzg.onrender.com/

## 🌍 The African Problem

Across Africa, phishing, fake job offers, banking scams, and identity theft threaten individuals and communities. Limited cybersecurity awareness and unequal access to smartphones and mobile internet leave many people vulnerable.

Fraud Lens addresses these challenges by providing accessible AI-powered scam detection and cybersecurity education through multiple communication channels, including SMS and USSD for users without mobile data.

## 💡 Our Solution

Fraud Lens combines artificial intelligence with practical cybersecurity education.

### Key Features

- 🔍 **AI Scam Detection:** Analyse suspicious messages using Google Gemini.
- 🚨 **Risk Assessment:** Identify potential scams and receive clear explanations and safety recommendations.
- 📚 **Cybersecurity Education:** Learn about phishing, OTP theft, banking fraud, and online scams through short lessons and quizzes.
- 💬 **WhatsApp Bot:** Forward suspicious messages and receive AI-powered fraud assessments.
- 📱 **SMS Integration:** Access scam detection through Africa's Talking SMS API.
- ☎️ **USSD Access:** Learn cybersecurity fundamentals using basic mobile phones without mobile internet.

All supported channels share the same AI-powered scam-analysis engine.

## 🛠️ Technologies Used

| Component | Technology |
|-----------|------------|
| Backend | Python, FastAPI |
| Frontend | HTML, CSS, JavaScript |
| Artificial Intelligence | Google Gemini API |
| WhatsApp Integration | Twilio WhatsApp API |
| SMS & USSD | Africa's Talking API |
| Hosting | Render |
| Development | VS Code, GitHub |

## 🚀 Running the Project Locally

### Prerequisites

- Python 3.13
- pip
- Google Gemini API key

### 1. Clone the Repository

```bash
git clone https://github.com/NomsaNG/fraud-lens
cd fraud-lens
```

### 2. Create a Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables

Create a `.env` file using `.env.example`.

Configure your Gemini API credentials:

```env
GEMINI_API_KEY=your_api_key
GEMINI_MODEL=gemini-3.5-flash-lite
```

For WhatsApp, SMS, and USSD functionality, configure the relevant Twilio and Africa's Talking credentials using `.env.example`.

### 5. Start Fraud Lens

```bash
uvicorn fraud_lens.app:app --reload --port 8000
```

Open:

http://localhost:8000

### 6. Run Tests

```bash
pytest -q
```

**Note:** External messaging integrations require valid API credentials and publicly accessible HTTPS webhook endpoints.

## ⚡ How We Kept Tokens Low

1. Used FastAPI and vanilla HTML, CSS, and JavaScript to minimise boilerplate and unnecessary framework code.
2. Reused one shared Gemini analysis function across web and messaging channels instead of duplicating functionality.
3. Kept development tasks focused, reused existing components, and avoided unnecessary abstractions and features.

## ✅ Project Status

**Working Demo**

- ✅ Web application deployed on Render.
- ✅ Gemini-powered scam analysis tested successfully.
- ✅ Twilio WhatsApp integration tested end to end.
- ✅ Automated tests passing.
- 🔄 Africa's Talking SMS and USSD implemented; live end-to-end testing pending.

## 🎯 Our Vision

Cybersecurity protection should not be a privilege reserved for people with smartphones, internet access, or technical knowledge.

**Fraud Lens aims to make digital safety education accessible to everyone across Africa.**

---

**Fraud Lens — Learn. Check. Stay Scam-Safe.**
