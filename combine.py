def combine_results(rule_result, ml_result, vt_result=None):
    rule_score = float(rule_result.get("rule_score", 0.0))

    ml_vote = int(ml_result.get("ml_final", 0))
    ml_confidence = float(ml_result.get("ml_confidence", 0.0))

    # Use ML score only if ML predicts phishing
    if ml_vote == 1:
        ml_score = ml_confidence
    else:
        ml_score = 0.0

    reasons = list(rule_result.get("rule_reasons", []))

    auth_result = rule_result.get(
        "email_authentication_result",
        {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}
    )

    vt_malicious = False
    vt_suspicious = False
    url_results = []

    if vt_result:
        url_results = vt_result.get("url_results", [])
        for item in url_results:
            vt_label = str(item.get("vt_label", "")).lower()
            if vt_label == "malicious":
                vt_malicious = True
            elif vt_label == "suspicious":
                vt_suspicious = True

    if vt_malicious:
        reasons.append("Malicious URL detected")
    elif vt_suspicious:
        reasons.append("Suspicious URL detected")

    # Base weighted score
    final_score = (0.4 * rule_score) + (0.6 * ml_score)

    # Auth failed check
    auth_failed = "Email authentication failed" in reasons

    # URL score
    if vt_malicious:
        final_score += 0.15

    if vt_suspicious:
        final_score += 0.08

    # Strong phishing score
    if vt_malicious and ml_vote == 1 and auth_failed:
        final_score = max(final_score, 0.90)

    if vt_malicious and ml_vote == 1 and rule_score >= 0.4:
        final_score = max(final_score, 0.85)

    final_score = min(final_score, 1.0)

    # Final classification logic
    if vt_malicious:
        if ml_score >= 0.70 or rule_score >= 0.60:
            final_label = "Phishing"
        else:
            final_label = "Suspicious"

    elif vt_suspicious:
        if final_score >= 0.65:
            final_label = "Phishing"
        else:
            final_label = "Suspicious"

    else:
        if final_score >= 0.70:
            final_label = "Phishing"
        elif final_score >= 0.40:
            final_label = "Suspicious"
        else:
            final_label = "Safe"

    if ml_vote == 1:
        reasons.append("ML model detected phishing patterns")
    else:
        reasons.append("ML model detected safe patterns")

    return {
        "final_label": final_label,
        "final_score": round(final_score, 2),
        "rule_score": round(rule_score, 2),
        "ml_score": round(ml_score, 2),
        "reasons": reasons,
        "email_authentication_result": auth_result,
        "url_results": url_results
    }