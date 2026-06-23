# SENTINEL
### AI-Powered Incident Response + Threat Intelligence Platform for Pakistani SMEs

> Built for small businesses, clinics, schools, and fintechs in Pakistan that face enterprise-grade threats with zero security budget.

---

## The Problem

98% of Pakistani SMEs have no incident response plan. When a breach happens, they google what to do, waste the critical first hours, collect weak evidence, and have no idea if the IP that emailed them is a known attacker. SENTINEL fixes all of that.

| What enterprises pay for | What SENTINEL replaces it with |
|--------------------------|-------------------------------|
| Splunk — $50,000/year | Log Analyzer with AI + 5 detection rules |
| CrowdStrike ThreatGraph — $500/month | Threat Intelligence Engine (7 free feeds) |
| IR consultants — $200/hour | Incident Manager + 10 built-in playbooks |
| Recorded Future TIP — $500/month | IOC Tracker with STIX 2.1 export |
| Digital forensics firms — $5,000/case | Evidence Vault + FIA-ready PDF reports |

---

## Features

**Threat Intelligence Engine**
- Checks any IP, domain, URL, file hash, or email address against 7 feeds simultaneously
- Feeds: AbuseIPDB, VirusTotal, AlienVault OTX, ThreatFox, IPinfo, URLhaus, MalwareBazaar
- Parallel queries with `asyncio.gather()` — 4 seconds instead of 21 seconds sequential
- 24-hour SQLite TTL cache to stay within free API rate limits
- Claude AI verdict: plain-English summary + specific recommended action

**Incident Manager**
- Submit an incident → AI automatically: classifies type + severity, extracts IOCs, maps MITRE ATT&CK techniques, generates 5-phase response playbook, checks PECA 2016 obligations
- 5-phase playbook: Contain → Investigate → Eradicate → Recover → Lessons Learned
- Pakistan-specific steps: FIA contacts, PECA reporting window, SBP/PTA guidance

**IOC Tracker**
- Central database of all indicators of compromise across all incidents
- Status lifecycle: Active → Blocked / Investigating → Resolved / False Positive
- Bulk re-check: refresh all active IOCs against feeds in one click
- Export as STIX 2.1 JSON bundle (international threat intelligence sharing standard)

**Log Analyzer**
- Upload Linux auth, Apache, Nginx, or any log file (up to 50MB)
- 5 detection rules: brute force, off-hours login, new admin account, suspicious URL patterns, impossible travel
- AI plain-English summary safe for non-technical business owners
- TI-flagged IPs: see if any log IP is a known malicious actor
- "Create Incident from Finding" button

**Evidence Vault**
- SHA-256 hash calculated on upload — proves file was not tampered with
- Chain of custody log for every access event
- FIA-ready PDF report: incident summary, timeline, IOCs, evidence with hashes, PECA section, MITRE ATT&CK

**10 Built-In Playbooks**
Ransomware, Phishing, Account Takeover, Data Breach, Insider Threat, DDoS, Social Engineering (BEC/CEO fraud), Lost Device, Vendor Breach, Malware — all with Pakistan-specific FIA/PECA steps.

**Dashboard**
- Risk score (0–100) calculated from open incidents by severity
- Incident trend charts (6 months), severity distribution, recent activity

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python 3.11 + FastAPI + asyncio |
| AI Engine | Anthropic Claude (claude-sonnet-4-6) |
| Database | SQLite + SQLAlchemy |
| Frontend | React 18 + TypeScript + Tailwind CSS + Recharts |
| PDF | ReportLab |
| IOC Standard | STIX 2.1 |
| Async HTTP | httpx |

---

## Setup

### Prerequisites
- Python 3.11+
- Node.js 18+
- Anthropic API key — minimum required (light use ~$1–5/month)

### Run Locally

```bash
# Clone
git clone https://github.com/YOUR_USERNAME/sentinel.git
cd sentinel

# Backend
cd backend
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux
pip install -r requirements.txt

# Configure
copy .env.example .env       # Windows
# cp .env.example .env       # macOS/Linux
# Edit .env — add ANTHROPIC_API_KEY at minimum

# Start backend
uvicorn main:app --reload --port 8000

# Frontend (new terminal)
cd ../frontend
npm install
npm run dev
```

Open **http://localhost:5173**

### API Keys

| Key | Where to Get | Free Tier |
|-----|-------------|-----------|
| `ANTHROPIC_API_KEY` | console.anthropic.com | Pay-per-use |
| `ABUSEIPDB_API_KEY` | abuseipdb.com/api | 1,000 checks/day |
| `VIRUSTOTAL_API_KEY` | virustotal.com | 500/day |
| `OTX_API_KEY` | otx.alienvault.com | Unlimited |
| `IPINFO_API_KEY` | ipinfo.io | 50,000/month |
| ThreatFox, URLhaus, MalwareBazaar | — | Unlimited, no key needed |

### First Steps

1. Go to **Settings** → enter your `ANTHROPIC_API_KEY`
2. **Threat Intel** → test with `185.220.101.45` (should return MALICIOUS — Tor exit node)
3. **Incidents** → Report New Incident → describe any phishing scenario → watch AI generate playbook
4. **Log Analyzer** → upload any `/var/log/auth.log` file

---

## Project Structure

```
sentinel/
├── backend/
│   ├── modules/
│   │   ├── threat_intel/   # 7 async feed functions + AI verdict + 24hr cache
│   │   ├── incidents/      # AI classifier + playbook generator + IOC extractor + MITRE mapper
│   │   ├── logs/           # Log parsers + 5 detection rules + AI analyst
│   │   ├── evidence/       # SHA-256 vault + PDF report generator (ReportLab)
│   │   ├── playbooks/      # 10 built-in playbooks
│   │   ├── iocs/           # STIX 2.1 export
│   │   └── notifications/  # SMTP email alerts
│   └── routers/            # 8 FastAPI routers
└── frontend/
    └── src/pages/          # Dashboard, ThreatIntel, Incidents, IOC, Logs, Playbooks, Settings
```

---

## API

Interactive docs at **http://localhost:8000/docs**

```
POST /api/ti/check                    # Check indicator against all feeds + AI verdict
POST /api/incidents                   # Submit incident → full AI pipeline
POST /api/logs/analyze                # Upload log file for analysis
GET  /api/iocs/export/stix            # Download STIX 2.1 bundle
GET  /api/incidents/{id}/report/pdf   # Download FIA-ready PDF report
GET  /api/dashboard/stats             # Risk score + all metrics
```

---

## Pakistan-Specific Features

- **PECA 2016** — Prevention of Electronic Crimes Act 2016 compliance detection; automatically flags incidents requiring FIA reporting with the correct section reference
- **FIA Cybercrime Wing** — `report.fia.gov.pk` | `0800-02345` | `cybercrime@fia.gov.pk` — contacts baked into every relevant playbook and PDF report
- **SBP / PTA** — sector-specific guidance for financial and telecom incidents
- **Pakistan SME framing** — AI responses tuned to small business constraints (limited IT staff, no SOC, Urdu-speaking stakeholders)

---

## License

MIT

---

*Manahil Khan — AI × Blue Team Security × Pakistan SME*
