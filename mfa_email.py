import os
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv

load_dotenv()

GMAIL_USER = os.getenv("GMAIL_USER")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")

print("GMAIL_USER =", GMAIL_USER)
print("GMAIL_APP_PASSWORD loaded =", bool(GMAIL_APP_PASSWORD))


def send_otp_email(receiver_email: str, otp: str):
    if not GMAIL_USER or not GMAIL_APP_PASSWORD:
        raise Exception("Gmail credentials are not configured in .env")

    subject = "Your PhishShield OTP Code"
    body = f"""
Hello,

Your OTP code for PhishShield login is: {otp}

Do not share this code with anyone.

Regards,
PhishShield
"""

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = GMAIL_USER
    msg["To"] = receiver_email

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
        server.sendmail(GMAIL_USER, receiver_email, msg.as_string())