# ScamBusters Agent

An AI-powered crypto scam investigation pipeline that automates OSINT collection, infrastructure mapping, and takedown request generation — with human review before any action is taken.

Built as part of the University of Tampa Center for Cybersecurity ScamBusters program.

---

## What it does

In a single run, ScamBusters Agent:

- Scrapes HYIP monitoring sites to discover active crypto investment scams
- Submits domains to URLScan for IP, ASN, hosting info, and visually similar sites
- Runs WHOIS lookups to identify registrars and abuse contacts
- Queries Passive DNS (CIRCL / ZETAlytics) for historical IPs, linked domains, and MX records
- Performs social media OSINT and Google Dorking to find promotional channels and wallet addresses
- Compiles a structured intelligence report per scam domain
- Presents findings for human review before generating formal takedown requests

---

## Pipeline stages

| Stage | Script | Description |
|---|---|---|
| 1 | `discover_scams.py` | Scrape HYIP monitor sites for live scam domains |
| 2 | `urlscan_lookup.py` | Submit domains to URLScan, collect infrastructure data |
| 3 | `whois_lookup.py` | WHOIS queries for registrar + abuse contacts |
| 4 | `passive_dns.py` | Passive DNS pivot via CIRCL (free) or ZETAlytics |
| 5 | `social_osint.py` | Google Dorking + Telegram/social link extraction |
| 6 | `report_generator.py` | AI-compiled scam profile (JSON + human summary) |
| 7 | `takedown_drafter.py` | Formal abuse email generation (human-approved only) |
| — | `app.py` | Flask dashboard for review and approval workflow |
| — | `agent.py` | Orchestrator — runs full pipeline end to end |

---

## Tech stack

- Python 3.10+
- Flask (review dashboard)
- OpenAI GPT-4 (report generation + takedown drafting)
- URLScan.io API
- Hunter.io API (recruiter/contact enrichment)
- CIRCL Passive DNS (free)
- ZETAlytics (optional, premium)
- python-whois
- BeautifulSoup4 + requests (scraping)

---

## Setup

```bash
git clone https://github.com/elijahbeese/scambusters-agent
cd scambusters-agent
pip install -r requirements.txt
cp .env.example .env
# Fill in your API keys in .env
python agent.py
```

To launch the review dashboard:

```bash
python app.py
```

---

## OpSec note

Always run investigations behind a VPN. Never enter real personal information on scam sites. The fake account / wallet harvesting step (Stage 5 manual) should be performed in a sandboxed VM.

---

## Project status

🚧 Active development — pipeline stages being built out sequentially.

---

## Based on

ScamBusters® curriculum — University of Tampa Center for Cybersecurity  
Built by Elijah Beese
