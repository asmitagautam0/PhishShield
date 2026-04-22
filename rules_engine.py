import re
from app.schemas import EmailInput


def extract_authentication_result(header_text: str):
    header = (header_text or "").lower()

    spf = "unknown"
    dkim = "unknown"
    dmarc = "unknown"

    spf_match = re.search(
        r"(?:received-spf:\s*|spf\s*=\s*)(pass|fail|softfail|neutral|none)",
        header
    )
    if spf_match:
        spf = spf_match.group(1)

    dkim_match = re.search(r"dkim\s*=\s*(pass|fail|none)", header)
    if dkim_match:
        dkim = dkim_match.group(1)

    dmarc_match = re.search(r"dmarc\s*=\s*(pass|fail|none|quarantine|reject)", header)
    if dmarc_match:
        dmarc = dmarc_match.group(1)

    return {
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc
    }


def detect_basic_grammar_issues(text: str):
    if not text:
        return False

    lowered_text = str(text).lower()

    grammar_error_patterns = [
        r"\bwe has\b",
        r"\bit require\b",
        r"\byou is\b",
        r"\bmay resulted\b",
        r"\binformations\b",
        r"\bthis may causes\b",
        r"\bwe apologies\b",
        r"\baccount have been suspended\b",
        r"\byour account are\b",
        r"\bhe go to\b",
        r"\bshe do not\b"
    ]

    for pattern in grammar_error_patterns:
        if re.search(pattern, lowered_text):
            return True

    return False


def run_rules(payload: EmailInput):
    body = (payload.body or "").lower()
    subject = (payload.subject or "").lower()
    sender = (payload.sender or "").lower()
    header = payload.header or ""

    score = 0.0
    reasons = []

    email_authentication_result = {
        "spf": "unknown",
        "dkim": "unknown",
        "dmarc": "unknown"
    }

    if header.strip():
        email_authentication_result = extract_authentication_result(header)

    # Suspicious wording checks
    suspicious_phrases = [
        "urgent",
        "immediately",
        "verify your account",
        "reset your password",
        "account suspended",
        "confirm your identity",
        "click here",
        "login now",
        "update your payment",
        "confirm your account"
    ]

    combined_text = f"{subject} {body}".strip()

    if combined_text and any(phrase in combined_text for phrase in suspicious_phrases):
        score += 0.10
        reasons.append("Urgent or suspicious wording detected")

    # Basic grammar issue detection
    if detect_basic_grammar_issues(f"{payload.subject or ''} {payload.body or ''}"):
        score += 0.03
        reasons.append("Possible grammatical issues detected")

    # Sender-name risk
    suspicious_sender_terms = ["security@", "admin@", "billing@"]
    if any(term in sender for term in suspicious_sender_terms):
        score += 0.08
        reasons.append("Potentially risky sender naming pattern")



    if "http://" in combined_text or "https://" in combined_text or "www." in combined_text:
        score += 0.02
        reasons.append("Link detected in email content")


    # Authentication block
    spf_status = email_authentication_result["spf"]
    dkim_status = email_authentication_result["dkim"]
    dmarc_status = email_authentication_result["dmarc"]

    fail_like_spf = ["fail", "softfail", "none", "unknown"]
    fail_like_dkim = ["fail", "none", "unknown"]
    fail_like_dmarc = ["fail", "none", "unknown", "quarantine", "reject"]

    # All PASS
    if spf_status == "pass" and dkim_status == "pass" and dmarc_status == "pass":
        reasons.append("Email authentication passed")

    # All failed / missing / suspicious
    elif (
        spf_status in fail_like_spf and
        dkim_status in fail_like_dkim and
        dmarc_status in fail_like_dmarc
    ):
        score += 0.30
        reasons.append("Email authentication failed")

    # Mixed cases
    else:
        if spf_status == "fail":
            score += 0.20
            reasons.append("SPF authentication failed")
        elif spf_status == "softfail":
            score += 0.12
            reasons.append("SPF authentication softfail")

        if dkim_status == "fail":
            score += 0.20
            reasons.append("DKIM authentication failed")

        if dmarc_status == "fail":
            score += 0.20
            reasons.append("DMARC authentication failed")
        elif dmarc_status in ["quarantine", "reject"]:
            score += 0.12
            reasons.append(f"DMARC authentication {dmarc_status}")

    score = min(score, 1.0)

    return {
        "engine": "rule",
        "rule_score": round(score, 3),
        "rule_reasons": reasons,
        "email_authentication_result": email_authentication_result
    }