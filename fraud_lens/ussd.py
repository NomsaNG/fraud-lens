import os

from .content import QUIZ

MENU = "CON Welcome to CyberShield Africa\n1. Learn about scams\n2. Banking and OTP safety\n3. Check a suspicious message\n4. Cybersecurity quiz\n5. Get a safety tip by SMS"


def _quiz(parts: list[str]) -> str:
    answers = parts[1:]
    if len(answers) > 3:
        return "END Session complete. Dial again to restart."
    for index, answer in enumerate(answers[:3]):
        if answer not in {"1", "2"}:
            return "END Invalid quiz answer. Dial again to retry."
    if len(answers) >= 3:
        score = sum(int(a) - 1 == q["answer"] for a, q in zip(answers[:3], QUIZ))
        return f"END Score: {score}/3. Never share an OTP or PIN. Verify requests independently."
    q = QUIZ[len(answers)]
    return f"CON Q{len(answers)+1}: {q['question']}\n1. {q['choices'][0]}\n2. {q['choices'][1]}"


def handle_ussd(text: str) -> tuple[str, bool]:
    """Return the provider response and whether a consented SMS tip is due."""
    if not text:
        return MENU, False
    parts = text.split("*")
    if len(parts) > 5 or any(len(x) > 120 for x in parts):
        return "END Session limit reached. Dial again to restart.", False
    root = parts[0]
    if root == "1":
        topics = {"1": "Phishing: fake links seek your details. Use the official app.", "2": "Fake jobs may demand upfront fees. Verify the employer.", "3": "Impostors copy names and logos. Call an official number.", "4": "Shopping scams offer unrealistic deals. Check the seller."}
        if len(parts) == 1:
            return "CON Learn about scams\n1. Phishing\n2. Fake jobs\n3. Impersonation\n4. Online shopping", False
        if len(parts) > 2:
            return "END Session complete. Dial again to restart.", False
        return ("END " + topics.get(parts[1], "Invalid topic. Dial again.")), False
    if root == "2":
        if len(parts) > 1:
            return "END Session complete. Dial again to restart.", False
        return "END Banks never need your OTP or PIN by text or phone. Verify alerts using your bank's app or official number.", False
    if root == "3":
        if len(parts) == 1:
            return "CON Choose a concern\n1. Bank/OTP\n2. Job offer\n3. Link or other message", False
        tips = {"1": "Never share an OTP or PIN. Call your bank officially.", "2": "Do not pay to get a job. Verify the employer.", "3": "Do not open a suspicious link. Verify the sender."}
        if parts[1] not in tips:
            return "END Invalid choice. Dial again.", False
        if len(parts) > 2:
            return "END Session complete. Dial again to restart.", False
        shortcode = os.getenv("AT_SMS_SHORTCODE", "the configured shortcode")
        return f"END {tips[parts[1]]} For AI analysis, text the full message to {shortcode}.", False
    if root == "4":
        return _quiz(parts), False
    if root == "5":
        if len(parts) == 1:
            return "CON Send one safety tip by SMS?\n1. Yes\n2. No", False
        if parts[1] == "1" and len(parts) == 2:
            return "END Your one-time safety tip is being sent.", True
        return "END No SMS sent.", False
    return "END Invalid choice. Dial again to restart.", False
