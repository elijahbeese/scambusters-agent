"""
Stage 2: urlscan_lookup.py
Submits domains to URLScan.io and retrieves:
- Primary IP, ASN, hosting info
- Visually similar sites (key for I4G cluster mapping)
- Screenshot URL
- Malicious verdict score

Per I4G docs: visual/structural similarity is the PRIMARY method for
clustering scam networks using shared templates.
"""

import os
import time
import requests
from dotenv import load_dotenv

load_dotenv()

URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "")
URLSCAN_SUBMIT  = "https://urlscan.io/api/v1/scan/"
URLSCAN_RESULT  = "https://urlscan.io/api/v1/result/{}/"
URLSCAN_SEARCH  = "https://urlscan.io/api/v1/search/"


def submit_scan(domain: str) -> str | None:
    headers = {
        "API-Key": URLSCAN_API_KEY,
        "Content-Type": "application/json",
    }
    payload = {
        "url": f"https://{domain}",
        "visibility": "public",
        "tags": ["cryptoscam", "scambusters-agent", "i4g"],
    }
    try:
        r = requests.post(URLSCAN_SUBMIT, headers=headers, json=payload, timeout=15)
        if r.status_code == 200:
            return r.json().get("uuid")
        print(f"      [!] URLScan submit failed ({r.status_code})")
        return None
    except Exception as e:
        print(f"      [!] URLScan submit error: {e}")
        return None


def fetch_result(uuid: str, retries: int = 8, wait: int = 12) -> dict:
    url = URLSCAN_RESULT.format(uuid)
    for attempt in range(retries):
        time.sleep(wait)
        try:
            r = requests.get(url, timeout=15)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
    return {}


def get_similar_sites(uuid: str) -> list:
    """
    Fetch visually/structurally similar sites from URLScan.
    This is the I4G method for finding scam clusters — one domain
    can reveal hundreds of clones using the same HYIP template.
    """
    if not uuid or not URLSCAN_API_KEY:
        return []
    try:
        headers = {"API-Key": URLSCAN_API_KEY}
        r = requests.get(
            f"{URLSCAN_SEARCH}?q=page.domain:{uuid}&size=50",
            headers=headers, timeout=15
        )
        if r.status_code != 200:
            return []
        results = r.json().get("results", [])
        similar = []
        for res in results:
            page = res.get("page", {})
            domain = page.get("domain")
            if domain:
                similar.append({
                    "domain": domain,
                    "ip": page.get("ip"),
                    "asn": page.get("asn"),
                    "country": page.get("country"),
                    "scan_id": res.get("task", {}).get("uuid"),
                })
        return similar
    except Exception:
        return []


def parse_urlscan_result(result: dict) -> dict:
    if not result:
        return {"error": "No result returned"}

    page  = result.get("page", {})
    task  = result.get("task", {})
    uuid  = task.get("uuid", "")

    return {
        "primary_ip": page.get("ip"),
        "asn_number": page.get("asn"),
        "asn_name": page.get("asnname"),
        "country": page.get("country"),
        "server": page.get("server"),
        "screenshot_url": f"https://urlscan.io/screenshots/{uuid}.png" if uuid else None,
        "report_url": f"https://urlscan.io/result/{uuid}/" if uuid else None,
        "malicious_score": result.get("verdicts", {}).get("overall", {}).get("score", 0),
        "categories": result.get("verdicts", {}).get("overall", {}).get("categories", []),
        "scan_uuid": uuid,
        "similar_count": len(result.get("lists", {}).get("urls", [])),
    }


def run_urlscan(domain: str) -> dict:
    if not URLSCAN_API_KEY:
        return {"error": "URLSCAN_API_KEY not set"}

    uuid = submit_scan(domain)
    if not uuid:
        return {"error": "Scan submission failed"}

    raw = fetch_result(uuid)
    parsed = parse_urlscan_result(raw)
    parsed["similar_domains"] = get_similar_sites(uuid)
    return parsed


if __name__ == "__main__":
    import sys, json
    domain = sys.argv[1] if len(sys.argv) > 1 else "aitimart.com"
    result = run_urlscan(domain)
    print(json.dumps(result, indent=2))
