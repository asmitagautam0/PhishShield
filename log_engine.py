import json
import uuid
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = BASE_DIR / "logs" / "analysis_logs.json"


def save_all_logs(logs):
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=2, ensure_ascii=False)


def load_logs():
    if not LOG_FILE.exists():
        return []

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            logs = json.load(f)

        changed = False
        for log in logs:
            if "id" not in log or not log["id"]:
                log["id"] = str(uuid.uuid4())
                changed = True

        if changed:
            save_all_logs(logs)

        return logs
    except:
        return []


def save_log(entry):
    logs = load_logs()
    logs.insert(0, entry)
    save_all_logs(logs)


def delete_log(log_id):
    if not log_id:
        return False

    logs = load_logs()
    updated_logs = [log for log in logs if str(log.get("id", "")) != str(log_id)]
    save_all_logs(updated_logs)
    return True


def create_log_entry(payload, final_result, vt_result):
    return {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now().isoformat(),
        "subject": payload.subject or final_result.get("extracted_subject", ""),
        "sender": payload.sender,
        "header": payload.header,
        "body": payload.body,
        "final_label": final_result.get("final_label"),
        "final_score": final_result.get("final_score"),
        "reasons": final_result.get("reasons", []),
        "email_authentication_result": final_result.get("email_authentication_result", {}),
        "urls_found": vt_result.get("urls_found", []),
        "url_results": vt_result.get("url_results", [])
    }