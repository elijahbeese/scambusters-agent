<div align="center">

```
███████╗ ██████╗ █████╗ ███╗   ███╗██████╗ ██╗   ██╗███████╗████████╗███████╗██████╗ ███████╗
██╔════╝██╔════╝██╔══██╗████╗ ████║██╔══██╗██║   ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗██╔════╝
███████╗██║     ███████║██╔████╔██║██████╔╝██║   ██║███████╗   ██║   █████╗  ██████╔╝███████╗
╚════██║██║     ██╔══██║██║╚██╔╝██║██╔══██╗██║   ██║╚════██║   ██║   ██╔══╝  ██╔══██╗╚════██║
███████║╚██████╗██║  ██║██║ ╚═╝ ██║██████╔╝╚██████╔╝███████║   ██║   ███████╗██║  ██║███████║
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═════╝  ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝
                                        A G E N T
```

**AI-powered crypto scam investigation. Automated OSINT. Human-approved takedowns.**

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=flat-square&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![OpenAI](https://img.shields.io/badge/GPT--4o-powered-412991?style=flat-square&logo=openai&logoColor=white)](https://openai.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active%20Development-orange?style=flat-square)]()

*Built for the University of Tampa Center for Cybersecurity — ScamBusters® Program*

</div>

---

## What is this?

Crypto investment scams (HYIPs) steal billions annually. They spin up fast, clone themselves across dozens of domains, and disappear before victims know what hit them.

**ScamBusters Agent** automates the investigation pipeline — from discovering active scam sites to mapping their full infrastructure to drafting formal takedown requests — so investigators can move faster than the scammers do.

You find scams. The agent does the legwork. You pull the trigger on takedowns.

---

## What it does in a single run

```
🔍  Discovers active crypto scam domains from HYIP monitoring sites
🌐  Submits each domain to URLScan — IP, ASN, hosting, visually similar sites
📋  Runs WHOIS — registrar, creation date, abuse contacts
🗄️  Queries Passive DNS — historical IPs, linked domains, MX/SOA records
📡  Extracts social media links, Telegram channels, and Google Dork queries
🤖  GPT-4o compiles a full intelligence report per domain
👁️  Presents findings for your review
📨  Drafts formal takedown emails to registrar + hosting provider on approval
```

---

## Pipeline

```
HYIP Monitors ──► URLScan ──► WHOIS ──► Passive DNS ──► Social OSINT
                                                              │
                                                              ▼
                                                    AI Report Generation
                                                              │
                                                              ▼
                                                    ┌─ Human Review ─┐
                                                    │                │
                                                  APPROVE         REJECT
                                                    │
                                                    ▼
                                           Takedown Drafts
                                      (Registrar + Hosting Provider)
```

| # | Script | What it does |
|---|--------|-------------|
| 1 | `discover_scams.py` | Scrapes HYIP monitor sites for live scam domains |
| 2 | `urlscan_lookup.py` | Submits to URLScan, collects infrastructure intel |
| 3 | `whois_lookup.py` | WHOIS queries — registrar, dates, abuse contacts |
| 4 | `passive_dns.py` | pDNS pivot via CIRCL (free) or ZETAlytics (premium) |
| 5 | `social_osint.py` | Social link extraction + Google Dork URL builder |
| 6 | `report_generator.py` | GPT-4o compiles structured scam intelligence report |
| 7 | `takedown_drafter.py` | Formal abuse emails — only fires after your approval |
| — | `agent.py` | Orchestrator — runs the full pipeline end to end |
| — | `app.py` | Flask dashboard — review findings, approve takedowns |

---

## Stack

| Layer | Tech |
|-------|------|
| Language | Python 3.10+ |
| AI | OpenAI GPT-4o |
| Web | Flask |
| DNS Intel | CIRCL Passive DNS (free) · ZETAlytics (optional) |
| Domain Intel | URLScan.io · python-whois |
| Contact Intel | Hunter.io |
| Scraping | BeautifulSoup4 · requests |

---

## Setup

```bash
git clone https://github.com/elijahbeese/scambusters-agent
cd scambusters-agent
pip install -r requirements.txt
cp .env.example .env
```

Fill in `.env` with your API keys, then:

```bash
# Run the full investigation pipeline
python agent.py

# Launch the review dashboard
python app.py
```

---

## API Keys

| Key | Required | Get it |
|-----|----------|--------|
| `OPENAI_API_KEY` | ✅ Yes | [platform.openai.com](https://platform.openai.com) |
| `URLSCAN_API_KEY` | ✅ Yes | [urlscan.io](https://urlscan.io) — free tier works |
| `HUNTER_API_KEY` | ✅ Yes | [hunter.io](https://hunter.io) — free tier works |
| `ZETALYTICS_API_KEY` | ⬜ Optional | Premium — defaults to CIRCL if not set |

---

## OpSec

> ⚠️ Always investigate behind a VPN.
> Never enter real personal information on scam sites.
> Run manual wallet harvesting (Stage 5) inside a sandboxed VM.
> These sites are adversarial infrastructure — treat them accordingly.

---

## Project status

🚧 **Active development** — pipeline stages being built out sequentially.

- [x] Repo scaffold + full pipeline skeleton
- [ ] Stage 1: HYIP scraper (in progress)
- [ ] Stage 2–4: API integrations
- [ ] Stage 5: Social OSINT automation
- [ ] Stage 6–7: AI report + takedown generation
- [ ] Flask dashboard UI

---

<div align="center">

Built by **Elijah Beese** · University of Tampa · Center for Cybersecurity

*ScamBusters® is a program of the BBB Educational Foundation of Eastern Carolinas*

</div>
