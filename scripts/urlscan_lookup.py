"""
Stage 2: urlscan_lookup.py
Submits a domain to URLScan.io and retrieves infrastructure data.
"""

import os
import time
import requests
from dotenv import load_dotenv

load_dotenv()

URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "")
URLSCAN_SUBMIT = "https://urlscan.io/api/v1/scan/"
URLSCAN_RESULT = "https://urlscan.io/api/v1/result/{uuid}/"


def submit_scan(domain: str) -> str | None:
    """Submit a domain for scanning. Returns the scan UUID."""
    headers = {
        "API-Key": URLSCAN_API_KEY,
        "Content-Type": "application/json",
    }
    payload = {
        "url": f"https://{domain}",
        "visibility": "public",
        "tags": ["cryptoscam", "scambusters-agent"],
    }

    try:
        r = requests.post(URLSCAN_SUBMIT, headers=headers, json=payload, timeout=15)
        if r.status_code == 200:
            return r.json().get("uuid")
        else:
            print(f"      [!] URLScan submit failed ({r.status_code}): {r.text[:100]}")
            return None
    except Exception as e:
        print(f"      [!] URLScan submit error: {e}")
        return None


def fetch_result(uuid: str, retries: int = 6, wait: int = 10) -> dict:
    """Poll for scan result. URLScan takes ~10-30s to process."""
    url = URLSCAN_RESULT.format(uuid=uuid)
    for attempt in range(retries):
        time.sleep(wait)
        try:
            r = requests.get(url, timeout=15)
            if r.status_code == 200:
                return r.json()
            elif r.status_code == 404:
                # Not ready yet
                continue
        except Exception as e:
            print(f"      [!] URLScan fetch error (attempt {attempt+1}): {e}")

    return {}


def parse_urlscan_result(result: dict) -> dict:
    """Extract the fields we care about from the raw URLScan result."""
    if not result:
        return {"error": "No result returned"}

    page = result.get("page", {})
    meta = result.get("meta", {})

    return {
        "primary_ip": page.get("ip"),
        "asn": page.get("asn"),
        "asn_name": page.get("asnname"),
        "country": page.get("country"),
        "server": page.get("server"),
        "similar_sites_count": len(result.get("lists", {}).get("urls", [])),
        "screenshot_url": f"https://urlscan.io/screenshots/{result.get('task', {}).get('uuid')}.png",
        "report_url": f"https://urlscan.io/result/{result.get('task', {}).get('uuid')}/",
        "malicious_score": result.get("verdicts", {}).get("overall", {}).get("score", 0),
        "categories": result.get("verdicts", {}).get("overall", {}).get("categories", []),
    }


def run_urlscan(domain: str) -> dict:
    """Full URLScan workflow: submit → wait → parse."""
    if not URLSCAN_API_KEY:
        return {"error": "URLSCAN_API_KEY not set"}

    uuid = submit_scan(domain)
    if not uuid:
        return {"error": "Scan submission failed"}

    raw = fetch_result(uuid)
    return parse_urlscan_result(raw)


if __name__ == "__main__":
    import sys
    domain = sys.argv[1] if len(sys.argv) > 1 else "aitimart.com"
    result = run_urlscan(domain)
    import json
    print(json.dumps(result, indent=2))
