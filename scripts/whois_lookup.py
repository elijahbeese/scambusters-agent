"""
Stage 3: whois_lookup.py
WHOIS queries for registrar, creation date, abuse contacts, and SOA email.

Per I4G docs: SOA email is KEY for clustering threat actors —
same SOA email across domains = same operator (e.g. momohbiz@gmail.com → 243 criminal domains).
"""

import whois as python_whois
import subprocess
import re


def run_whois(domain: str) -> dict:
    result = {
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "registrar_abuse_email": None,
        "registrar_abuse_phone": None,
        "name_servers": [],
        "registrant_country": None,
        "org": None,
        "soa_email": None,
        "raw_emails": [],
    }

    # Primary: python-whois library
    try:
        w = python_whois.whois(domain)

        creation = w.creation_date
        if isinstance(creation, list): creation = creation[0]

        expiry = w.expiration_date
        if isinstance(expiry, list): expiry = expiry[0]

        emails = w.emails
        if isinstance(emails, str): emails = [emails]
        emails = list(set(emails or []))

        result.update({
            "registrar": w.registrar,
            "creation_date": str(creation) if creation else None,
            "expiration_date": str(expiry) if expiry else None,
            "name_servers": list(w.name_servers or []),
            "registrant_country": w.country,
            "org": w.org,
            "raw_emails": emails,
        })

        # Best guess at abuse email (prefer ones with 'abuse' in them)
        abuse_emails = [e for e in emails if "abuse" in e.lower()]
        result["registrar_abuse_email"] = abuse_emails[0] if abuse_emails else (emails[0] if emails else None)

    except Exception as e:
        result["error"] = str(e)

    # SOA email via dig (critical for I4G clustering methodology)
    try:
        soa_raw = subprocess.run(
            ["dig", "+short", "SOA", domain],
            capture_output=True, text=True, timeout=10
        ).stdout.strip()

        if soa_raw:
            # SOA format: primary_ns admin_email serial refresh retry expire ttl
            parts = soa_raw.split()
            if len(parts) >= 2:
                # SOA email uses dots instead of @ — first dot becomes @
                soa_email_raw = parts[1].rstrip(".")
                # Convert first dot to @
                at_idx = soa_email_raw.find(".")
                if at_idx > 0:
                    soa_email = soa_email_raw[:at_idx] + "@" + soa_email_raw[at_idx+1:]
                    result["soa_email"] = soa_email
    except Exception:
        pass

    return result


if __name__ == "__main__":
    import sys, json
    domain = sys.argv[1] if len(sys.argv) > 1 else "aitimart.com"
    result = run_whois(domain)
    print(json.dumps(result, indent=2, default=str))
