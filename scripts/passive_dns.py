"""
Stage 4: passive_dns.py
Queries Passive DNS for historical IPs, linked domains, and MX records.
Uses CIRCL (free) by default, ZETAlytics if API key is present.
"""

import os
import requests
from dotenv import load_dotenv

load_dotenv()

ZETALYTICS_KEY = os.getenv("ZETALYTICS_API_KEY", "")

# CIRCL Passive DNS (free, no key required)
CIRCL_PDNS_URL = "https://www.circl.lu/pdns/query/{domain}"


def query_circl(domain: str) -> dict:
    """Query CIRCL free Passive DNS service."""
    try:
        url = CIRCL_PDNS_URL.format(domain=domain)
        r = requests.get(url, timeout=15)

        if r.status_code != 200:
            return {"error": f"CIRCL returned {r.status_code}"}

        records = []
        for line in r.text.strip().splitlines():
            try:
                import json
                record = json.loads(line)
                records.append(record)
            except Exception:
                continue

        # Parse out what we care about
        ips = list({r["rdata"] for r in records if r.get("rrtype") == "A"})
        mx_records = [r["rdata"] for r in records if r.get("rrtype") == "MX"]
        linked_domains = list({r["rrname"] for r in records if r.get("rrtype") in ("A", "CNAME")})

        return {
            "source": "CIRCL",
            "historical_ips": ips,
            "mx_records": mx_records,
            "linked_domains": linked_domains,
            "raw_record_count": len(records),
        }

    except Exception as e:
        return {"error": str(e)}


def query_zetalytics(domain: str) -> dict:
    """Query ZETAlytics Passive DNS (premium). Falls back to CIRCL if no key."""
    if not ZETALYTICS_KEY:
        return query_circl(domain)

    try:
        url = f"https://zonecruncher.com/api/v1/hostname2ip?q={domain}&token={ZETALYTICS_KEY}"
        r = requests.get(url, timeout=15)

        if r.status_code != 200:
            return {"error": f"ZETAlytics returned {r.status_code}"}

        data = r.json()
        results = data.get("results", [])

        ips = list({entry.get("ip") for entry in results if entry.get("ip")})
        linked_domains = list({entry.get("d") for entry in results if entry.get("d")})

        return {
            "source": "ZETAlytics",
            "historical_ips": ips,
            "linked_domains": linked_domains,
            "raw_record_count": len(results),
        }

    except Exception as e:
        return {"error": str(e)}


def run_passive_dns(domain: str) -> dict:
    """Run passive DNS query — ZETAlytics if available, else CIRCL."""
    if ZETALYTICS_KEY:
        return query_zetalytics(domain)
    return query_circl(domain)


if __name__ == "__main__":
    import sys, json
    domain = sys.argv[1] if len(sys.argv) > 1 else "aitimart.com"
    result = run_passive_dns(domain)
    print(json.dumps(result, indent=2))
