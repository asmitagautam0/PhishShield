from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.mfa_email import send_otp_email
import random
from app.schemas import EmailInput, LoginInput, OTPVerifyInput, URLInput
from app.rules_engine import run_rules
from app.ml_engine import run_ml
from app.combine import combine_results
from app.virustotal_engine import analyze_urls, check_single_url
from app.log_engine import save_log, create_log_entry, load_logs, delete_log
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

otp_store = {}

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3001",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {"message": "PhishShield backend running"}

@app.post("/api/analyze")
def analyze(payload: EmailInput):
    full_email_text = f"""
Header: {payload.header or ""}
Subject: {payload.subject or ""}
Sender: {payload.sender or ""}
Body: {payload.body or ""}
""".strip()

    body_text = (payload.body or "").strip()
    header_text = (payload.header or "").strip()

    # Block very short / incomplete input
    word_count = len(full_email_text.split())

    if word_count < 25 or (not header_text and len(body_text.split()) < 20):
        return {
            "final_label": "Insufficient Input",
            "final_score": 0.0,
            "rule_score": 0.0,
            "ml_score": 0.0,
            "reasons": [
                "Paste full email message for accurate result."
            ],
            "email_authentication_result": {
                "spf": "unknown",
                "dkim": "unknown",
                "dmarc": "unknown"
            },
            "urls_found": [],
            "url_results": []
        }

    rule_result = run_rules(payload)
    ml_result = run_ml(full_email_text)
    vt_result = analyze_urls((payload.header or "") + "\n" + (payload.body or ""))
    final_result = combine_results(rule_result, ml_result, vt_result)

    log_entry = create_log_entry(payload, final_result, vt_result)
    save_log(log_entry)

    return {
        **final_result,
        "urls_found": vt_result["urls_found"],
        "url_results": vt_result["url_results"]
    }

@app.get("/api/logs")
def get_logs():
    return {"logs": load_logs()}

@app.delete("/api/logs/{log_id}")
def remove_log(log_id: str):
    delete_log(log_id)
    return {"message": "Log deleted successfully"}

@app.post("/api/login")
def login(payload: LoginInput):
    valid_email = os.getenv("ADMIN_EMAIL")
    valid_password = os.getenv("ADMIN_PASSWORD")

    if payload.email == valid_email and payload.password == valid_password:
        otp = str(random.randint(100000, 999999))
        otp_store[payload.email] = otp

        try:
            send_otp_email(payload.email, otp)
        except Exception as e:
            return {
                "success": False,
                "message": f"Failed to send OTP email: {str(e)}"
            }

        return {
            "success": True,
            "mfa_required": True,
            "message": "OTP sent to your Gmail."
        }

    return {
        "success": False,
        "message": "Invalid email or password"
    }

@app.post("/api/verify-otp")
def verify_otp(payload: OTPVerifyInput):
    saved_otp = otp_store.get(payload.email)

    if saved_otp and saved_otp == payload.otp:
        del otp_store[payload.email]
        return {
            "success": True,
            "message": "MFA verification successful"
        }

    return {
        "success": False,
        "message": "Invalid OTP"
    }

@app.post("/api/check-url")
def check_url(payload: URLInput):
    clean_url = (payload.url or "").strip()
    result = check_single_url(clean_url)
    return result