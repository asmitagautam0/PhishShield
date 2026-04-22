import os
import time
import base64
import requests
import re
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
VT_BASE = "https://www.virustotal.com/api/v3"


def looks_like_base64(text: str):
    if not text:
        return False

    cleaned = re.sub(r"\s+", "", text)

    if len(cleaned) < 40:
        return False

    return re.fullmatch(r"[A-Za-z0-9+/=]+", cleaned) is not None


def decode_base64_content(text: str):
    if not text:
        return text

    try:
        cleaned = re.sub(r"\s+", "", text)

        # Add missing padding if required
        missing_padding = len(cleaned) % 4
        if missing_padding:
            cleaned += "=" * (4 - missing_padding)

        decoded = base64.b64decode(cleaned).decode("utf-8", errors="ignore")
        return decoded
    except Exception:
        return text


def extract_urls(raw_text: str):
    raw_text = raw_text or ""

    # normal visible URLs
    url_regex = r"(https?://[^\s<>\"]+|www\.[^\s<>\"]+)"
    found = re.findall(url_regex, raw_text)

    # href links from HTML
    href_regex = r'href=["\'](https?://[^"\']+)["\']'
    href_found = re.findall(href_regex, raw_text, re.IGNORECASE)

    all_urls = found + href_found

    cleaned = []
    for u in all_urls:
        u = u.strip()
        if u.lower().startswith("www."):
            u = "http://" + u
        cleaned.append(u)

    return list(dict.fromkeys(cleaned))


def _url_id(url: str):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def scan_url_with_virustotal(url: str):
    if not VT_API_KEY:
        return {
            "url": url,
            "status": "error",
            "message": "VirusTotal API key not configured"
        }

    headers = {"x-apikey": VT_API_KEY}

    try:
        submit = requests.post(
            f"{VT_BASE}/urls",
            headers=headers,
            data={"url": url},
            timeout=20
        )
        submit.raise_for_status()

        submit_data = submit.json()
        analysis_id = submit_data.get("data", {}).get("id")

        # Gather analysis result
        if analysis_id:
            for _ in range(4):
                time.sleep(3)

                analysis_res = requests.get(
                    f"{VT_BASE}/analyses/{analysis_id}",
                    headers=headers,
                    timeout=20
                )
                analysis_res.raise_for_status()

                analysis_data = analysis_res.json().get("data", {})
                attrs = analysis_data.get("attributes", {})
                status = attrs.get("status", "")

                if status == "completed":
                    stats = attrs.get("stats", {})

                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)
                    undetected = stats.get("undetected", 0)

                    if malicious > 0:
                        vt_label = "malicious"
                    elif suspicious > 0:
                        vt_label = "suspicious"
                    else:
                        vt_label = "clean"

                    return {
                        "url": url,
                        "status": "ok",
                        "vt_label": vt_label,
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "harmless": harmless,
                        "undetected": undetected,
                        "last_analysis_date": attrs.get("date"),
                    }

        return {
            "url": url,
            "status": "error",
            "message": "VirusTotal analysis not ready yet. Please try again."
        }

    except requests.HTTPError as e:
        return {
            "url": url,
            "status": "error",
            "message": f"HTTP error: {str(e)}"
        }
    except Exception as e:
        return {
            "url": url,
            "status": "error",
            "message": str(e)
        }


def analyze_urls(raw_text: str, max_urls: int = 3):
    text_to_check = raw_text or ""

    #normal/plain-text URL extraction
    urls = extract_urls(text_to_check)

    #extract base64 MIME body and decode it
    if not urls:
        lines = text_to_check.splitlines()
        collecting_base64 = False
        base64_chunks = []

        for line in lines:
            lower = line.lower().strip()

            if "content-transfer-encoding: base64" in lower:
                collecting_base64 = True
                base64_chunks = []
                continue

            if collecting_base64:
                if line.startswith("--"):
                    joined = "\n".join(base64_chunks).strip()
                    if looks_like_base64(joined):
                        decoded_text = decode_base64_content(joined)
                        urls = extract_urls(decoded_text)
                        if urls:
                            break
                    collecting_base64 = False
                    base64_chunks = []
                    continue

                if line.strip():
                    base64_chunks.append(line.strip())

        # Final option
        if not urls and looks_like_base64(text_to_check):
            decoded_text = decode_base64_content(text_to_check)
            urls = extract_urls(decoded_text)

    urls = urls[:max_urls]
    results = [scan_url_with_virustotal(url) for url in urls]

    return {
        "urls_found": urls,
        "url_results": results
    }


def normalize_single_url(url: str):
    if not url:
        return ""

    url = url.strip()

    # remove accidental spaces/newlines inside pasted URL
    url = re.sub(r"\s+", "", url)

    # remove common trailing punctuation from pasted text
    url = url.rstrip('.,);]>\'"')

    # if scheme is missing, add https
    if url.lower().startswith("www."):
        url = "http://" + url
    elif not url.lower().startswith(("http://", "https://")):
        url = "https://" + url

    return url


def check_single_url(url: str):
    clean_url = normalize_single_url(url)

    if not clean_url:
        return {
            "url": "",
            "status": "error",
            "message": "No URL provided"
        }

    return scan_url_with_virustotal(clean_url)