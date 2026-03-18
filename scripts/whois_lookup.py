"""
Stage 3: whois_lookup.py
Runs WHOIS queries to identify registrar, creation date, and abuse contacts.
"""

import whois


def run_whois(domain: str) -> dict:
    """
    Query WHOIS for a domain and extract investigation-relevant fields.
    """
    try:
        w = whois.whois(domain)

        # Creation date can be a list or a single value
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]

        expiry = w.expiration_date
        if isinstance(expiry, list):
            expiry = expiry[0]

        return {
            "registrar": w.registrar,
            "creation_date": str(creation) if creation else None,
            "expiration_date": str(expiry) if expiry else None,
            "registrar_abuse_email": w.emails[0] if isinstance(w.emails, list) and w.emails else w.emails,
            "name_servers": w.name_servers,
            "status": w.status,
            "registrant_country": w.country,
            "org": w.org,
        }

    except Exception as e:
        return {"error": str(e)}


if __name__ == "__main__":
    import sys, json
    domain = sys.argv[1] if len(sys.argv) > 1 else "aitimart.com"
    result = run_whois(domain)
    print(json.dumps(result, indent=2, default=str))
