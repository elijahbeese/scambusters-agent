"""
Stage 4: passive_dns.py
Passive DNS pivot via CIRCL (free) or ZETAlytics (premium).

Per I4G docs: pDNS is critical for:
- Finding linked domains via shared IPs
- Discovering admin panels (e.g. aitiusers.com from aitimart.com)
- Clustering scam networks by SOA email and shared infrastructure
- Tracking domain operator across registrar changes
"""

import os
import requests
import json
from dotenv import load_dotenv

load_dotenv()

ZETALYTICS_KEY = os.getenv("ZETALYTICS_API_KEY", "")
CIRCL_URL      = "https://www.circl.lu/pdns/query/{domain}"
ZETALYTICS_BASE = "https://zonecruncher.com/api/v1"


def query_circl(domain: str) -> dict:
    """CIRCL free Passive DNS — no key required."""
    try:
        r = requests.get(CIRCL_URL.format(domain=domain), timeout=15)
        if r.status_code != 200:
            return {"error": f"CIRCL returned {r.status_code}", "source": "CIRCL"}

        records = []
        for line in r.text.strip().splitlines():
            try:
                records.append(json.loads(line))
            except Exception:
                continue

        a_records   = [rec for rec in records if rec.get("rrtype") == "A"]
        mx_records  = [rec for rec in records if rec.get("rrtype") == "MX"]
        soa_records = [rec for rec in records if rec.get("rrtype") == "SOA"]
        ns_records  = [rec for rec in records if rec.get("rrtype") == "NS"]

        historical_ips = list({r["rdata"] for r in a_records if r.get("rdata")})
        mx_hosts       = list({r["rdata"] for r in mx_records if r.get("rdata")})
        soa_data       = [r["rdata"] for r in soa_records if r.get("rdata")]
        linked_domains = list({r["rrname"].rstrip(".") for r in records
                               if r.get("rrname") and r["rrname"].rstrip(".") != domain})

        return {
            "source": "CIRCL",
            "historical_ips": historical_ips,
            "mx_records": mx_hosts,
            "soa_records": soa_data,
            "linked_domains": linked_domains[:50],
            "raw_record_count": len(records),
        }
    except Exception as e:
        return {"error": str(e), "source": "CIRCL"}


def query_zetalytics_domain(domain: str) -> dict:
    """ZETAlytics domain → IP history + linked domains."""
    try:
        r = requests.get(
            f"{ZETALYTICS_BASE}/hostname2ip",
            params={"q": domain, "token": ZETALYTICS_KEY},
            timeout=15
        )
        if r.status_code != 200:
            return {}
        data = r.json()
        results = data.get("results", [])
        ips = list({e.get("ip") for e in results if e.get("ip")})
        domains = list({e.get("d") for e in results if e.get("d")})
        return {"historical_ips": ips, "linked_domains": domains}
    except Exception:
        return {}


def query_zetalytics_ip(ip: str) -> list:
    """ZETAlytics IP → what other domains have used this IP."""
    try:
        r = requests.get(
            f"{ZETALYTICS_BASE}/ip2hostname",
            params={"q": ip, "token": ZETALYTICS_KEY},
            timeout=15
        )
        if r.status_code != 200:
            return []
        data = r.json()
        results = data.get("results", [])
        return list({e.get("d") for e in results if e.get("d")})
    except Exception:
        return []


def query_zetalytics_soa(email: str) -> list:
    """
    ZETAlytics SOA email reverse lookup.
    Per I4G: momohbiz@gmail.com → 243 criminal domains.
    This is the nuclear option for attributing a threat actor.
    """
    try:
        r = requests.get(
            f"{ZETALYTICS_BASE}/email2soa",
            params={"q": email, "token": ZETALYTICS_KEY},
            timeout=15
        )
        if r.status_code != 200:
            return []
        data = r.json()
        results = data.get("results", [])
        return list({e.get("d") for e in results if e.get("d")})
    except Exception:
        return []


def run_passive_dns(domain: str, soa_email: str = None) -> dict:
    """Full pDNS investigation — ZETAlytics if available, else CIRCL."""
    if ZETALYTICS_KEY:
        base = query_zetalytics_domain(domain)
        result = {
            "source": "ZETAlytics",
            "historical_ips": base.get("historical_ips", []),
            "linked_domains": base.get("linked_domains", []),
            "mx_records": [],
            "soa_records": [],
        }
        # Pivot on each discovered IP to find more linked domains
        all_ip_domains = []
        for ip in result["historical_ips"][:3]:
            ip_domains = query_zetalytics_ip(ip)
            all_ip_domains.extend(ip_domains)
        result["ip_pivot_domains"] = list(set(all_ip_domains) - {domain})[:50]

        # SOA email reverse lookup — the I4G clustering method
        if soa_email:
            result["soa_cluster_domains"] = query_zetalytics_soa(soa_email)

    else:
        result = query_circl(domain)
        result["ip_pivot_domains"] = []

    return result


if __name__ == "__main__":
    import sys
    domain = sys.argv[1] if len(sys.argv) > 1 else "aitimart.com"
    import json
    r = run_passive_dns(domain)
    print(json.dumps(r, indent=2))
