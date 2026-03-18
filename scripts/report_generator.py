"""
Stage 6: report_generator.py
Uses GPT-4 to compile a structured scam intelligence report
from all collected OSINT data.
"""

import os
import json
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

SYSTEM_PROMPT = """You are a cybersecurity analyst specializing in crypto investment scam investigations.
You receive raw OSINT data collected about a fraudulent cryptocurrency investment site and produce
a concise, structured intelligence report suitable for law enforcement referral or registrar takedown requests.

Your report must include:
1. Threat summary (2-3 sentences)
2. Infrastructure overview (IP, hosting, registrar)
3. Threat actor indicators (linked domains, email patterns, MX records)
4. Social media footprint
5. Recommended takedown targets (registrar + hosting provider)
6. Risk level: LOW / MEDIUM / HIGH / CRITICAL

Be direct and factual. Do not hedge. This is an internal investigator report, not public-facing."""


def generate_report(scam_data: dict) -> dict:
    """
    Feed all collected OSINT into GPT-4 and return a structured report.
    """
    domain = scam_data.get("domain", "unknown")

    # Build a clean summary of what we collected
    osint_summary = {
        "domain": domain,
        "urlscan": scam_data.get("urlscan", {}),
        "whois": scam_data.get("whois", {}),
        "passive_dns": scam_data.get("passive_dns", {}),
        "social_osint": scam_data.get("social_osint", {}),
    }

    prompt = f"""Analyze the following OSINT data for the crypto investment scam site: {domain}

Data collected:
{json.dumps(osint_summary, indent=2, default=str)}

Generate a complete intelligence report following the format in your instructions."""

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
        )

        report_text = response.choices[0].message.content

        return {
            "status": "success",
            "domain": domain,
            "report": report_text,
            "model": "gpt-4o",
        }

    except Exception as e:
        return {
            "status": "error",
            "domain": domain,
            "error": str(e),
        }


if __name__ == "__main__":
    # Test with mock data
    mock_data = {
        "domain": "aitimart.com",
        "urlscan": {"primary_ip": "79.143.87.241", "asn_name": "Hydra Communications Ltd", "country": "GB"},
        "whois": {"registrar": "WebNic.cc", "creation_date": "2023-08-27", "registrar_abuse_email": "abuse@webnic.cc"},
        "passive_dns": {"historical_ips": ["79.143.87.241"], "linked_domains": ["aitiusers.com"]},
        "social_osint": {"social_links": {"telegram": ["https://t.me/aitimart_official"]}},
    }
    result = generate_report(mock_data)
    print(result["report"])
