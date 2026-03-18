"""
Stage 5: social_osint.py
Extracts social media links, Telegram/WhatsApp channels, contact info.
Builds Google Dork queries per I4G methodology.

Per I4G docs: scammers promote via:
- Telegram announcement channels
- WhatsApp "force join" groups  
- Facebook groups (Free BTC, Bitcoin Mining Worldwide, etc.)
- Affiliate referral codes across social media
"""

import requests
from bs4 import BeautifulSoup
import re
import time

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

SOCIAL_PATTERNS = {
    "telegram":  r"https?://(?:t\.me|telegram\.me)/[^\s\"'>]+",
    "whatsapp":  r"https?://chat\.whatsapp\.com/[^\s\"'>]+",
    "facebook":  r"https?://(?:www\.)?facebook\.com/[^\s\"'>]+",
    "instagram": r"https?://(?:www\.)?instagram\.com/[^\s\"'>]+",
    "twitter":   r"https?://(?:www\.)?(?:twitter|x)\.com/[^\s\"'>]+",
    "youtube":   r"https?://(?:www\.)?youtube\.com/[^\s\"'>]+",
    "tiktok":    r"https?://(?:www\.)?tiktok\.com/[^\s\"'>]+",
}

WALLET_PATTERNS = {
    "bitcoin":  r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
    "ethereum": r"\b0x[a-fA-F0-9]{40}\b",
    "tron":     r"\bT[A-Za-z1-9]{33}\b",
    "usdt_trc20": r"\bT[A-Za-z1-9]{33}\b",
    "bnb":      r"\b0x[a-fA-F0-9]{40}\b",
}


def scrape_site(url: str, timeout: int = 10) -> str:
    """Fetch page HTML safely."""
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout)
        return r.text
    except Exception:
        return ""


def extract_social_links(html: str) -> dict:
    found = {platform: [] for platform in SOCIAL_PATTERNS}
    for platform, pattern in SOCIAL_PATTERNS.items():
        matches = re.findall(pattern, html)
        found[platform] = list(set(matches))
    return found


def extract_contact_info(html: str) -> dict:
    emails = list(set(re.findall(
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", html
    )))
    phones = list(set(re.findall(
        r"\+?[\d\s\-\(\)]{10,20}", html
    )))
    phones = [p.strip() for p in phones if len(p.strip()) >= 10][:20]
    return {"emails": emails, "phones": phones}


def extract_wallets_from_html(html: str) -> dict:
    """
    Extract crypto wallet addresses from HTML.
    Per I4G docs: create fake account → go to deposit page → harvest wallet addresses.
    This attempts automated extraction from public HTML first.
    """
    wallets = {}
    for currency, pattern in WALLET_PATTERNS.items():
        matches = list(set(re.findall(pattern, html)))
        if matches:
            wallets[currency] = matches
    return wallets


def scrape_scam_site_osint(domain: str) -> dict:
    """
    Visit the scam site and extract all OSINT from public pages.
    Checks homepage, /contact, /support, /about pages.
    """
    all_social = {platform: [] for platform in SOCIAL_PATTERNS}
    all_contact = {"emails": [], "phones": []}
    all_wallets = {}

    pages = [
        f"https://{domain}",
        f"https://{domain}/contact",
        f"https://{domain}/contact-us",
        f"https://{domain}/support",
        f"https://{domain}/about",
    ]

    for url in pages:
        html = scrape_site(url)
        if not html:
            continue

        social = extract_social_links(html)
        for platform, links in social.items():
            all_social[platform].extend(links)

        contact = extract_contact_info(html)
        all_contact["emails"].extend(contact["emails"])
        all_contact["phones"].extend(contact["phones"])

        wallets = extract_wallets_from_html(html)
        for currency, addrs in wallets.items():
            all_wallets.setdefault(currency, []).extend(addrs)

        time.sleep(1)

    # Deduplicate
    for platform in all_social:
        all_social[platform] = list(set(all_social[platform]))
    all_contact["emails"] = list(set(all_contact["emails"]))
    all_contact["phones"] = list(set(all_contact["phones"]))
    for currency in all_wallets:
        all_wallets[currency] = list(set(all_wallets[currency]))

    return {
        "social_links": all_social,
        "contact_info": all_contact,
        "wallets_from_html": all_wallets,
    }


def build_google_dorks(domain: str) -> dict:
    """
    Build Google Dork query URLs per I4G methodology.
    intitle: and intext: operators to find promotional content
    not visible from the scam site itself.
    """
    name = domain.split(".")[0]
    return {
        "intitle_domain": f'https://www.google.com/search?q=intitle:"{name}"',
        "intitle_full": f'https://www.google.com/search?q=intitle:"{domain}"',
        "intext_domain": f'https://www.google.com/search?q=intext:"{domain}"',
        "site_references": f'https://www.google.com/search?q="{domain}"+-site:{domain}',
        "telegram_promo": f'https://www.google.com/search?q=site:t.me+"{name}"',
        "facebook_groups": f'https://www.google.com/search?q=site:facebook.com+"{name}"',
        "tiktok_promo": f'https://www.google.com/search?q=site:tiktok.com+"{name}"',
        "referral_codes": f'https://www.google.com/search?q="{domain}"+ref+OR+referral+OR+invite',
        "note": "Run manually or integrate SerpAPI for automation.",
    }


def run_social_osint(domain: str) -> dict:
    site_data = scrape_scam_site_osint(domain)
    dorks = build_google_dorks(domain)

    return {
        "social_links": site_data["social_links"],
        "contact_info": site_data["contact_info"],
        "wallets_from_html": site_data["wallets_from_html"],
        "google_dorks": dorks,
    }


if __name__ == "__main__":
    import sys, json
    domain = sys.argv[1] if len(sys.argv) > 1 else "aitimart.com"
    result = run_social_osint(domain)
    print(json.dumps(result, indent=2))
