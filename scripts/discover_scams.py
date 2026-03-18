"""
Stage 1: discover_scams.py
Scrapes HYIP monitoring sites to extract live crypto investment scam domains.
Also supports URLScan tag search (task.tags:cryptoscam) per I4G docs.
"""

import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import time
import random

HYIP_MONITORS = [
    "https://www.tophyip.biz/",
    "https://bestemoneys.com/hyips_1.html",
    "https://phyip.com/",
    "https://hyipbanker.com/",
    "https://www.hothyips.com/",
]

URLSCAN_TAG_SEARCH = "https://urlscan.io/api/v1/search/?q=task.tags:cryptoscam&size=100"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

SKIP_DOMAINS = {
    "google.com", "facebook.com", "twitter.com", "t.me",
    "telegram.org", "youtube.com", "instagram.com", "linkedin.com",
    "wikipedia.org", "github.com", "urlscan.io",
}


def extract_domains_from_monitor(url: str) -> list:
    domains = []
    try:
        r = requests.get(url, headers=HEADERS, timeout=12)
        soup = BeautifulSoup(r.text, "lxml")
        monitor_netloc = urlparse(url).netloc

        for a in soup.find_all("a", href=True):
            href = a["href"]
            parsed = urlparse(href)
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                continue
            domain = parsed.netloc.replace("www.", "").lower()
            if domain == monitor_netloc.replace("www.", ""):
                continue
            if any(skip in domain for skip in SKIP_DOMAINS):
                continue
            if domain and domain not in domains:
                domains.append(domain)
    except Exception as e:
        print(f"      [!] Failed scraping {url}: {e}")
    return domains


def discover_from_urlscan_tags(api_key: str = None) -> list:
    """
    Query URLScan for domains tagged 'cryptoscam' per I4G methodology.
    Returns list of domains.
    """
    headers = {}
    if api_key:
        headers["API-Key"] = api_key
    try:
        r = requests.get(URLSCAN_TAG_SEARCH, headers=headers, timeout=15)
        if r.status_code != 200:
            return []
        results = r.json().get("results", [])
        domains = []
        for result in results:
            page = result.get("page", {})
            domain = page.get("domain", "")
            if domain and domain not in domains:
                domains.append(domain)
        return domains
    except Exception as e:
        print(f"      [!] URLScan tag search failed: {e}")
        return []


def discover_scam_domains(max_domains: int = 20, urlscan_api_key: str = None) -> list:
    all_domains = []

    # Method 1: HYIP monitors
    for monitor in HYIP_MONITORS:
        print(f"      Scraping: {monitor}")
        domains = extract_domains_from_monitor(monitor)
        all_domains.extend(domains)
        time.sleep(random.uniform(1.5, 3.0))

    # Method 2: URLScan cryptoscam tag (per I4G docs)
    if urlscan_api_key:
        print("      Querying URLScan cryptoscam tag...")
        tag_domains = discover_from_urlscan_tags(urlscan_api_key)
        all_domains.extend(tag_domains)

    # Deduplicate
    seen = set()
    unique = []
    for d in all_domains:
        if d not in seen:
            seen.add(d)
            unique.append(d)

    return unique[:max_domains]


if __name__ == "__main__":
    domains = discover_scam_domains(max_domains=10)
    print(f"\nDiscovered {len(domains)} domains:")
    for d in domains:
        print(f"  {d}")
