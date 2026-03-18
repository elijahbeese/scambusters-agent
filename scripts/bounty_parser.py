"""
bounty_parser.py
Parses raw Discord bounty message text into structured data.

Example Discord message:
🎯 New Bounty: edx50.com Information Intelligence For Good daily bounty.
Get it before it expires!
Sponsor Intelligence For Good
Multiplier ×1.25
Max Claims 1
Expires in 17 hours • March 18, 2026 at 8:00 PM
Target https://edx50.com/
Bounty ID: 20260317_7e70bc8d882b4ac9a48307e4dd0ee75b
"""

import re
from datetime import datetime
from urllib.parse import urlparse


def parse_bounty(raw_text: str) -> dict:
    """
    Parse a raw Discord bounty message into structured fields.
    Returns a dict with all extracted fields, None for anything not found.
    """
    text = raw_text.strip()
    result = {
        "raw": text,
        "title": None,
        "domain": None,
        "target_url": None,
        "sponsor": None,
        "multiplier": None,
        "max_claims": None,
        "expires_raw": None,
        "bounty_id": None,
        "parsed_at": datetime.utcnow().isoformat(),
        "status": "pending",
    }

    # Title — first line after emoji
    title_match = re.search(r"(?:🎯\s*)?New Bounty:\s*(.+?)(?:\n|$)", text)
    if title_match:
        result["title"] = title_match.group(1).strip()

    # Target URL
    url_match = re.search(r"Target\s+(https?://\S+)", text)
    if url_match:
        result["target_url"] = url_match.group(1).strip().rstrip("/")
        parsed = urlparse(result["target_url"])
        result["domain"] = parsed.netloc.replace("www.", "")

    # Fallback: extract domain from title line
    if not result["domain"] and result["title"]:
        domain_match = re.search(
            r"([a-zA-Z0-9][a-zA-Z0-9\-]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)",
            result["title"]
        )
        if domain_match:
            result["domain"] = domain_match.group(1)

    # Sponsor
    sponsor_match = re.search(r"Sponsor\s+(.+?)(?:\n|$)", text)
    if sponsor_match:
        result["sponsor"] = sponsor_match.group(1).strip()

    # Multiplier
    mult_match = re.search(r"Multiplier\s+[×x]?([\d.]+)", text)
    if mult_match:
        result["multiplier"] = float(mult_match.group(1))

    # Max claims
    claims_match = re.search(r"Max Claims?\s+(\d+)", text)
    if claims_match:
        result["max_claims"] = int(claims_match.group(1))

    # Expiry
    expires_match = re.search(
        r"Expires.*?(?:•\s*)?((?:January|February|March|April|May|June|July|August|"
        r"September|October|November|December)\s+\d{1,2},\s+\d{4}(?:\s+at\s+[\d:]+\s*[AP]M)?)",
        text, re.IGNORECASE
    )
    if expires_match:
        result["expires_raw"] = expires_match.group(1).strip()

    # Bounty ID
    id_match = re.search(r"Bounty ID[:\s]+([a-zA-Z0-9_]+)", text)
    if id_match:
        result["bounty_id"] = id_match.group(1).strip()

    return result


def validate_bounty(parsed: dict) -> tuple[bool, list[str]]:
    """
    Validate that a parsed bounty has the minimum required fields.
    Returns (is_valid, list_of_errors).
    """
    errors = []
    if not parsed.get("domain"):
        errors.append("Could not extract target domain")
    if not parsed.get("bounty_id"):
        errors.append("No Bounty ID found — double-check the paste")
    return len(errors) == 0, errors


if __name__ == "__main__":
    test = """🎯 New Bounty: edx50.com Information Intelligence For Good daily bounty. Get it before it expires! Sponsor Intelligence For Good Multiplier ×1.25 Max Claims 1 Expires in 17 hours • March 18, 2026 at 8:00 PM Target https://edx50.com/ Bounty ID: 20260317_7e70bc8d882b4ac9a48307e4dd0ee75b"""
    import json
    result = parse_bounty(test)
    print(json.dumps(result, indent=2))
    valid, errors = validate_bounty(result)
    print(f"\nValid: {valid}")
    if errors:
        print(f"Errors: {errors}")
