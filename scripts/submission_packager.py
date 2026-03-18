"""
submission_packager.py
Formats completed investigation into an I4G submission package.
Output: structured dict ready for email to sam@intelligenceForGood.org
"""

import json
from datetime import datetime


def build_submission_package(bounty: dict, investigation: dict) -> dict:
    """
    Build the complete I4G submission package from bounty metadata
    and investigation results.
    """
    domain    = bounty.get("domain", "unknown")
    whois     = investigation.get("whois", {})
    urlscan   = investigation.get("urlscan", {})
    pdns      = investigation.get("passive_dns", {})
    social    = investigation.get("social_osint", {})
    wallets   = investigation.get("wallets", {})
    similar   = investigation.get("similar_domains", [])
    report    = investigation.get("ai_report", {})

    # Aggregate all wallet addresses
    all_wallets = {}
    # From dedicated wallet harvest
    if isinstance(wallets, dict):
        all_wallets.update(wallets)
    # From social OSINT HTML scrape
    if isinstance(social, dict):
        html_wallets = social.get("wallets_from_html", {})
        for currency, addrs in html_wallets.items():
            all_wallets.setdefault(currency, [])
            all_wallets[currency] = list(set(all_wallets[currency] + addrs))

    # Aggregate all linked/similar domains
    all_linked = list(set(
        (pdns.get("linked_domains") or []) +
        (pdns.get("ip_pivot_domains") or []) +
        (pdns.get("soa_cluster_domains") or []) +
        [s.get("domain") for s in (similar or []) if s.get("domain")]
    ) - {domain})

    # Social media channels
    social_links = social.get("social_links", {}) if isinstance(social, dict) else {}
    channels = {}
    for platform, links in social_links.items():
        if links:
            channels[platform] = links

    package = {
        "submission_metadata": {
            "bounty_id":   bounty.get("bounty_id"),
            "sponsor":     bounty.get("sponsor", "Intelligence For Good"),
            "submitted_at": datetime.utcnow().isoformat(),
            "tool":        "ScamBusters Agent v1.0",
            "contact":     "[YOUR NAME / EMAIL]",
        },
        "target": {
            "domain":       domain,
            "url":          bounty.get("target_url") or f"https://{domain}",
            "primary_ip":   urlscan.get("primary_ip"),
            "asn":          urlscan.get("asn_name"),
            "country":      urlscan.get("country"),
            "screenshot":   urlscan.get("screenshot_url"),
            "urlscan_report": urlscan.get("report_url"),
        },
        "registration": {
            "registrar":          whois.get("registrar"),
            "creation_date":      whois.get("creation_date"),
            "abuse_email":        whois.get("registrar_abuse_email"),
            "abuse_phone":        whois.get("registrar_abuse_phone"),
            "soa_email":          whois.get("soa_email"),
            "name_servers":       whois.get("name_servers", []),
        },
        "linked_domains":       all_linked,
        "linked_domain_count":  len(all_linked),
        "crypto_wallets":       all_wallets,
        "wallet_count":         sum(len(v) for v in all_wallets.values()),
        "social_channels":      channels,
        "intelligence_report":  report.get("report") if isinstance(report, dict) else str(report),
        "google_dorks":         social.get("google_dorks", {}) if isinstance(social, dict) else {},
    }

    return package


def format_email_body(package: dict) -> str:
    """Format submission package as a clean email body for sam@intelligenceForGood.org"""
    target   = package.get("target", {})
    reg      = package.get("registration", {})
    meta     = package.get("submission_metadata", {})
    wallets  = package.get("crypto_wallets", {})
    linked   = package.get("linked_domains", [])
    channels = package.get("social_channels", {})

    wallet_str = "\n".join(
        f"  {currency.upper()}: {addr}"
        for currency, addrs in wallets.items()
        for addr in addrs
    ) or "  None identified"

    linked_str = "\n".join(f"  - {d}" for d in linked[:20]) or "  None identified"
    if len(linked) > 20:
        linked_str += f"\n  ... and {len(linked)-20} more"

    channels_str = "\n".join(
        f"  {platform}: {link}"
        for platform, links in channels.items()
        for link in links
    ) or "  None identified"

    body = f"""Subject: ScamBusters Bounty Submission — {target.get('domain')} [{meta.get('bounty_id')}]

Hello Sam,

Please find below the investigation results for bounty {meta.get('bounty_id')}.

---
TARGET DOMAIN: {target.get('domain')}
URL: {target.get('url')}
URLScan Report: {target.get('urlscan_report', 'N/A')}

INFRASTRUCTURE:
  Primary IP: {target.get('primary_ip')}
  ASN / Hosting: {target.get('asn')} ({target.get('country')})
  Registrar: {reg.get('registrar')}
  Registered: {reg.get('creation_date')}
  Registrar Abuse: {reg.get('abuse_email')}
  SOA Email: {reg.get('soa_email')} ← key for actor clustering

LINKED DOMAINS ({package.get('linked_domain_count')} total):
{linked_str}

CRYPTO WALLETS ({package.get('wallet_count')} addresses):
{wallet_str}

SOCIAL MEDIA / PROMO CHANNELS:
{channels_str}

---
INTELLIGENCE REPORT:
{package.get('intelligence_report', 'See attached JSON')}

---
Generated by ScamBusters Agent v1.0
{meta.get('contact')}
"""
    return body
