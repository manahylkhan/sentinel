# SENTINEL — Complete User Guide & Methodology
### AI-Powered Incident Response + Threat Intelligence for Small Businesses
**Version 1.0 | Confidential | Prepared for Manahil Khan**

---

## Table of Contents

1. [What is SENTINEL?](#1-what-is-sentinel)
2. [The Problem It Solves](#2-the-problem-it-solves)
3. [Architecture & Technology Stack](#3-architecture--technology-stack)
4. [Setup & Installation](#4-setup--installation)
5. [Getting Your Free API Keys](#5-getting-your-free-api-keys)
6. [Module 1 — Threat Intelligence Engine](#6-module-1--threat-intelligence-engine)
7. [Module 2 — Incident Manager](#7-module-2--incident-manager)
8. [Module 3 — IOC Tracker](#8-module-3--ioc-tracker)
9. [Module 4 — Log Analyzer](#9-module-4--log-analyzer)
10. [Module 5 — Playbook Library](#10-module-5--playbook-library)
11. [Module 6 — Evidence Vault](#11-module-6--evidence-vault)
12. [Module 7 — Dashboard](#12-module-7--dashboard)
13. [Settings & Configuration](#13-settings--configuration)
14. [Technical Methodology](#14-technical-methodology)
15. [Pakistan-Specific Features](#15-pakistan-specific-features)
16. [Common Scenarios — Step by Step](#16-common-scenarios--step-by-step)
17. [API Reference](#17-api-reference)
18. [Troubleshooting](#18-troubleshooting)
19. [Portfolio Context](#19-portfolio-context)

---

## 1. What is SENTINEL?

SENTINEL is a self-hosted AI-powered cybersecurity platform designed specifically for **small and medium businesses in Pakistan** — organizations that face the same threats as large enterprises but have none of their budget or personnel.

A small clinic in Lahore, a school in Karachi, a boutique fintech in Islamabad: none of them can afford Splunk ($50,000/year), CrowdStrike, or a Security Operations Center. But all of them face ransomware, phishing, account takeovers, and data breaches daily.

SENTINEL gives them:
- A **non-technical interface** — a business owner or their IT person can use this without a cybersecurity degree
- **AI-powered analysis** — Claude (Anthropic) provides plain-English explanations of complex threats
- **Free threat intelligence** — integrates 7+ free threat feeds that would otherwise cost hundreds of dollars/month
- **Pakistan-specific guidance** — FIA Cybercrime Wing contacts, PECA 2016 obligations, SBP/PTA reporting built into every workflow

### What SENTINEL Replaces

| Enterprise Tool | Cost | SENTINEL Alternative |
|----------------|------|---------------------|
| Splunk (SIEM) | $50,000+/year | Log Analyzer |
| CrowdStrike ThreatGraph | $500+/month | Threat Intelligence Engine |
| Mandiant/IBM IR consultants | $200+/hour | Incident Manager + Playbooks |
| Recorded Future (TIP) | $500+/month | IOC Tracker |
| Digital forensics firms | $5,000+/case | Evidence Vault + PDF Reports |

---

## 2. The Problem It Solves

### The Reality for Pakistani SMEs

- **98%** of Pakistani SMEs have no incident response plan
- **206 days** — average time for an SME to detect a breach (IBM Cost of a Data Breach Report)
- When a breach happens: the business owner googles what to do, wastes the critical first hours, collects weak evidence
- **PECA 2016** requires reporting certain cyber incidents to FIA — most SMEs don't know this and miss the window
- No affordable threat intelligence — they don't know if the IP emailing them is a known attacker
- Police/FIA reports fail because evidence is disorganized and lacks forensic integrity

### How SENTINEL Addresses This

```
Incident Happens
      ↓
Log it in SENTINEL (2 minutes)
      ↓
AI classifies: ransomware / phishing / breach / etc. (10 seconds)
      ↓
AI generates step-by-step response playbook (15 seconds)
      ↓
IOCs extracted from description automatically
      ↓
Check any suspicious IPs/domains against 7 threat feeds (4 seconds)
      ↓
Upload evidence with integrity hashing
      ↓
Generate FIA-ready PDF report
      ↓
Know your PECA 2016 obligations before the window closes
```

Total time from "something bad happened" to "I have a plan and evidence": **under 5 minutes**.

---

## 3. Architecture & Technology Stack

### System Overview

```
┌──────────────────────────────────────────────────────────┐
│                     SENTINEL                              │
│                                                          │
│  ┌─────────────┐         ┌────────────────────────────┐  │
│  │  React 18   │ ←HTTP→  │   FastAPI Backend           │  │
│  │  TypeScript │  /api/  │   Python 3.11              │  │
│  │  Tailwind   │         │   asyncio + httpx          │  │
│  └─────────────┘         └────────────┬───────────────┘  │
│                                       │                  │
│                          ┌────────────┴───────────────┐  │
│                          │         Modules             │  │
│                          │                            │  │
│                          │  threat_intel/  → 7 feeds  │  │
│                          │  incidents/     → Claude   │  │
│                          │  logs/          → parsers  │  │
│                          │  evidence/      → vault    │  │
│                          │  playbooks/     → 10 PBs   │  │
│                          │  notifications/ → email    │  │
│                          └────────────┬───────────────┘  │
│                                       │                  │
│                          ┌────────────┴───────────────┐  │
│                          │    SQLite Database          │  │
│                          │    (sentinel.db)            │  │
│                          │                            │  │
│                          │  ti_cache                  │  │
│                          │  incidents                 │  │
│                          │  incident_timeline         │  │
│                          │  iocs                      │  │
│                          │  evidence                  │  │
│                          │  custody_log               │  │
│                          │  playbooks                 │  │
│                          └────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
          │                                │
          ↓                                ↓
  External TI Feeds               Anthropic Claude API
  (AbuseIPDB, VT,                 (claude-sonnet-4-6)
   OTX, ThreatFox,
   IPinfo, URLhaus,
   MalwareBazaar)
```

### Technology Choices and Why

| Component | Technology | Why This Choice |
|-----------|-----------|-----------------|
| Backend framework | FastAPI | Async support for parallel TI feed queries; automatic OpenAPI docs; type safety |
| Database | SQLite | Zero setup, portable, runs locally; perfect for SME deployment |
| AI engine | Claude claude-sonnet-4-6 | Best-in-class for structured JSON output; understands security context deeply |
| Async HTTP | httpx + asyncio | Parallel feed queries — 7 feeds simultaneously instead of sequentially |
| Frontend | React 18 + TypeScript | Type safety, component reuse; industry standard |
| Styling | Tailwind CSS | Dark theme security aesthetic; rapid development |
| Charts | Recharts | Lightweight, React-native charting |
| PDF reports | ReportLab | Python-native PDF generation; no external services |
| IOC format | STIX 2.1 | International standard for threat intelligence sharing |

### Database Schema

```
ti_cache          → stores TI check results with 24hr TTL (avoids re-querying)
incidents         → all incident records with AI analysis embedded as JSON
incident_timeline → chronological action log per incident
iocs              → all indicators of compromise across all incidents
evidence          → uploaded files with SHA-256 integrity hashes
custody_log       → chain of custody for every evidence file access
playbooks         → 10 built-in + any custom playbooks
```

### File Structure

```
sentinel/
├── backend/
│   ├── main.py                    ← FastAPI app, route registration, startup
│   ├── config.py                  ← Settings from .env (pydantic-settings)
│   ├── database.py                ← SQLAlchemy engine + session factory
│   ├── models.py                  ← All DB table definitions
│   ├── .env                       ← Your API keys (never commit this)
│   ├── requirements.txt
│   ├── sentinel.db                ← SQLite database (auto-created)
│   ├── evidence_files/            ← Uploaded evidence files
│   │
│   ├── modules/
│   │   ├── threat_intel/
│   │   │   ├── feeds.py           ← 7 feed check functions (all async)
│   │   │   ├── cache.py           ← 24hr SQLite TTL cache
│   │   │   └── ai_verdict.py      ← Claude verdict generation
│   │   │
│   │   ├── incidents/
│   │   │   ├── classifier.py      ← Claude incident classification
│   │   │   ├── playbook.py        ← Claude playbook generation
│   │   │   ├── ioc_extractor.py   ← Regex + Claude IOC extraction
│   │   │   └── mitre_mapper.py    ← Claude MITRE ATT&CK mapping
│   │   │
│   │   ├── logs/
│   │   │   ├── detector.py        ← Detect log format from content
│   │   │   ├── rules.py           ← 5 detection rules (brute force, etc.)
│   │   │   ├── ai_analyst.py      ← Claude log analysis
│   │   │   └── parsers/
│   │   │       ├── linux_auth.py  ← /var/log/auth.log parser
│   │   │       ├── apache.py      ← Apache/Nginx access log parser
│   │   │       └── generic.py     ← Fallback for unknown formats
│   │   │
│   │   ├── evidence/
│   │   │   ├── vault.py           ← File storage + SHA-256 hashing
│   │   │   └── report_generator.py← PDF report via ReportLab
│   │   │
│   │   ├── playbooks/
│   │   │   └── builtin_loader.py  ← 10 pre-built playbooks
│   │   │
│   │   ├── iocs/
│   │   │   └── stix_export.py     ← STIX 2.1 JSON bundle export
│   │   │
│   │   └── notifications/
│   │       └── email_notifier.py  ← SMTP email alerts
│   │
│   └── routers/
│       ├── threat_intel.py        ← POST /api/ti/check, /bulk-check, /history
│       ├── incidents.py           ← CRUD + /timeline, /status
│       ├── iocs.py                ← CRUD + /bulk-check, /export/stix
│       ├── logs.py                ← POST /api/logs/analyze
│       ├── evidence.py            ← Upload, download, report
│       ├── playbooks.py           ← CRUD + /apply/{incident_id}
│       ├── dashboard.py           ← GET /api/dashboard/stats
│       └── settings.py            ← GET/POST /api/settings
│
└── frontend/
    └── src/
        ├── App.tsx                ← Routes
        ├── components/
        │   └── Sidebar.tsx        ← Navigation
        └── pages/
            ├── Dashboard.tsx
            ├── ThreatIntel.tsx
            ├── Incidents/
            │   ├── IncidentList.tsx
            │   ├── NewIncident.tsx
            │   └── IncidentDetail.tsx
            ├── IOCTracker.tsx
            ├── LogAnalyzer.tsx
            ├── PlaybookLibrary.tsx
            └── Settings.tsx
```

---

## 4. Setup & Installation

### Prerequisites

- **Python 3.11 or 3.12** — check with `python --version`
- **Node.js 18+** — check with `node --version`
- At minimum: **Anthropic API key** (the only one you need to pay for — typically $1-5/month for light use)

### Step-by-Step Installation

#### Step 1 — Backend Setup

```bash
cd e:\Sentinel\sentinel\backend

# Create virtual environment
python -m venv venv

# Activate it (Windows)
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

#### Step 2 — Configure API Keys

Open `backend\.env` and add your keys:

```env
ANTHROPIC_API_KEY=sk-ant-api03-...your-key...
ABUSEIPDB_API_KEY=...
VIRUSTOTAL_API_KEY=...
OTX_API_KEY=...
IPINFO_API_KEY=...
```

See [Section 5](#5-getting-your-free-api-keys) for where to get each key.

#### Step 3 — Start the Backend

```bash
# From backend/ with venv active:
uvicorn main:app --reload --port 8000
```

You should see:
```
INFO:     Started server process
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000
```

The database (`sentinel.db`) is created automatically. The 10 built-in playbooks are loaded on first startup.

#### Step 4 — Start the Frontend

```bash
# New terminal:
cd e:\Sentinel\sentinel\frontend
npm install      # only needed first time
npm run dev
```

Open **http://localhost:5173** in your browser.

#### Step 5 — First Login

1. Go to **Settings** (bottom of sidebar)
2. Enter your `ANTHROPIC_API_KEY` and click Save
3. Optionally add the free TI feed keys
4. Go to **Threat Intel** and test with `8.8.8.8` (Google DNS — should be CLEAN)
5. Test with `185.220.101.45` (Tor exit node — should be MALICIOUS)

---

## 5. Getting Your Free API Keys

### Anthropic (Required)

The only paid service. Light usage costs $1–5/month.

1. Go to **console.anthropic.com**
2. Sign up / Log in
3. Click **API Keys** → **Create Key**
4. Copy the key starting with `sk-ant-api03-...`

### AbuseIPDB (1,000 free checks/day)

1. Go to **abuseipdb.com**
2. Sign up for free account
3. Go to **API** in your profile
4. Create a key and copy it

### VirusTotal (500 free queries/day)

1. Go to **virustotal.com**
2. Sign up for free account
3. Go to your **Profile** → **API Key**
4. Copy the 64-character key

### AlienVault OTX (Unlimited free)

1. Go to **otx.alienvault.com**
2. Sign up for free account
3. Go to **Settings** → **API Integration**
4. Copy your OTX Key

### IPinfo (50,000 free requests/month)

1. Go to **ipinfo.io**
2. Sign up for free account
3. Go to **Account** → **Token**
4. Copy your token

### No Key Needed (Always Free)

- **ThreatFox** (abuse.ch) — automatically queried
- **URLhaus** (abuse.ch) — automatically queried
- **MalwareBazaar** (abuse.ch) — automatically queried

---

## 6. Module 1 — Threat Intelligence Engine

### What It Does

Checks any IP address, domain, URL, file hash, or email address against 7 free threat intelligence feeds simultaneously and gives you an AI-written verdict in plain English.

### How to Use It

1. Click **Threat Intel** in the sidebar
2. Paste any indicator in the input box:
   - **IP address**: `185.220.101.45`
   - **Domain**: `micros0ft-helpdesk.com`
   - **URL**: `http://malicious.example.com/payload.exe`
   - **File hash**: `a1b2c3d4...` (MD5/SHA1/SHA256)
   - **Email**: `invoice@suspicious-domain.pk`
3. The type is detected automatically — you'll see a badge like "IP Address" or "Domain"
4. Click **Check Threat Feeds**
5. Watch the feeds light up as they respond (parallel, takes 3–8 seconds)
6. Read the AI verdict

### Reading the Results

**Verdict Badge:**
- 🔴 **MALICIOUS** — This indicator is known bad. Take action immediately.
- 🟠 **SUSPICIOUS** — Something is wrong but not definitively confirmed. Investigate.
- 🟢 **CLEAN** — No feeds flagged this. Still use caution.
- ⚪ **UNKNOWN** — Not enough data to conclude.

**AI Summary** — 2–3 sentences explaining what the data means in plain English for a non-technical reader.

**Recommended Action** — Specific thing to do right now (e.g., "Block this IP at your firewall immediately").

**Feed Results Table** — What each source said:

| Feed | What It Checks |
|------|---------------|
| AbuseIPDB | Community reports of malicious IPs (100k+ daily reports) |
| VirusTotal | 70+ antivirus engine scan results |
| AlienVault OTX | Global threat intelligence from security researchers |
| ThreatFox | Malware command-and-control infrastructure |
| IPinfo | Geolocation, ISP, whether it's a VPN/Tor exit node |
| URLhaus | Known malware distribution URLs |
| MalwareBazaar | Known malware file hashes |

### Bulk Check

For checking multiple indicators at once:
- Use the API: `POST /api/ti/bulk-check` with up to 50 indicators

### Caching

Results are cached for 24 hours to avoid hitting API rate limits. Cached results show a "cached" badge. The same indicator checked twice in 24 hours returns the stored result instantly.

### Auto-IOC Creation

If the verdict is MALICIOUS or SUSPICIOUS, the indicator is automatically added to your IOC Tracker with status "active".

---

## 7. Module 2 — Incident Manager

### What It Does

The core workflow for handling a security incident from first detection through containment, investigation, recovery, and lessons learned. AI classifies what happened and generates a custom step-by-step response plan.

### Reporting a New Incident

1. Click **Incidents** → **Report New Incident** (blue button, top right)
2. Fill in the form:
   - **Title**: Short description (e.g., "Ransomware on accounts PC")
   - **Description**: Detailed description of what happened — **the more detail you give, the better the AI playbook**. Include any suspicious IPs, emails, file names you noticed.
   - **Affected Systems**: Which computers/servers/services are affected
   - **Your Name & Email**: Who is reporting
3. Click **Submit Incident Report**
4. Wait 10–15 seconds while AI processes
5. You'll be taken to the incident detail page with the full playbook

### What AI Does Automatically

When you submit an incident, in one API call sequence:

1. **Classification** — Determines: incident type (ransomware/phishing/etc.), severity (critical/high/medium/low), what data types are at risk, whether PECA 2016 reporting is required
2. **Playbook generation** — Creates a 5-phase response plan specific to YOUR incident with Pakistan-specific steps
3. **MITRE ATT&CK mapping** — Tags which attacker techniques were used (links to attack.mitre.org)
4. **IOC extraction** — Scans your description for IPs, domains, hashes, emails and adds them to the IOC Tracker
5. **Notifications** — Sends email alerts if critical severity or PECA reporting required

### Reading the Incident Detail Page

**PECA Alert** (orange box, appears when required):
> This tells you PECA 2016 reporting to FIA is required and gives you the exact contact details. Do not ignore this.

**AI Classification Card:**
- Severity reason — why this severity level was chosen
- Affected data types — PII, financial, credentials, etc.
- Immediate actions — top 3 things to do RIGHT NOW

**MITRE ATT&CK Badges:**
- Clickable technique IDs (e.g., T1566 — Phishing)
- Link to the MITRE ATT&CK knowledge base for more detail on how attackers execute this technique

**Playbook (5 Phases):**

| Phase | Purpose | Time Target |
|-------|---------|------------|
| Immediate Containment | Stop the bleeding | Within 1 hour |
| Investigation | Understand what happened | Within 4 hours |
| Eradication | Remove the threat | Within 24 hours |
| Recovery | Restore normal operations | Within 72 hours |
| Lessons Learned | Fix what allowed this to happen | Within 1 week |

**Using the Playbook Checklist:**
- Check off each step as you complete it
- ✅ Checked steps turn green and are crossed out
- 🔴 CRITICAL steps are highlighted — do these first
- Your progress is saved in the browser (persists through page refresh)
- Shows owner (IT/Management/HR/Legal), time estimate, and detailed instructions

**Pakistan-Specific Steps** (green box):
- FIA Cybercrime Wing contact details when criminal reporting is needed
- PECA 2016 specific obligations
- SBP reporting for financial organizations
- PTA contacts for telecom businesses

**Notify List:**
- Who needs to be told about this incident
- Why they need to know
- Script hints for what to say

### Managing Incidents

**Status Lifecycle:**
```
New → Investigating → Contained → Recovering → Closed
```

Change status with the dropdown on the incident detail page. Closing sets the close timestamp.

**Timeline:**
- All status changes and actions are logged automatically
- Add your own entries: "Isolated affected machine", "Called FIA", etc.
- Chronological log of the entire incident response

**Filtering the Incident List:**
- Filter by status: new / investigating / contained / recovering / closed
- Filter by severity: critical / high / medium / low

---

## 8. Module 3 — IOC Tracker

### What It Does

A centralized database of all Indicators of Compromise (IOCs) — malicious IPs, domains, hashes, URLs, and email addresses — from all your incidents, TI checks, and log analyses.

### Adding IOCs

**Automatic** — IOCs are added automatically from:
- Threat Intel checks with malicious/suspicious verdict
- Incident descriptions (AI extracts them)
- Log analysis (IPs found in logs that are flagged)

**Manual** — Click **+ Add IOC**:
- Enter the value, select type, set severity, add notes
- Useful for IOCs you find externally (threat reports, vendor alerts)

### IOC Status Lifecycle

```
Active → Blocked / Investigating → Resolved / False Positive
```

Change status with the dropdown in each row. Use this to track your remediation:
- **Active** — Known threat, not yet blocked
- **Blocked** — You've blocked this at firewall/email gateway
- **Investigating** — Looking into it
- **Resolved** — Threat is gone
- **False Positive** — Turned out to be safe

### Bulk Re-Check

Click **🔄 Bulk Re-Check** to re-run all Active IOCs against threat feeds. Updates their verdicts. Useful to run weekly — an IOC that was Unknown when added may now be classified.

### Export STIX 2.1

Click **📦 Export STIX** to download a STIX 2.1 JSON bundle of all your IOCs.

**What is STIX 2.1?** — The international standard format for sharing threat intelligence. You can:
- Share with other organizations who use compatible TIP tools
- Submit to sector-specific ISACs
- Import into other security tools
- Provide to FIA with your incident report

### Pattern Detection

When the same IOC appears in multiple incidents, you can spot it in the IOC list because it will be linked to an incident. This helps identify repeat attackers or persistent threats.

---

## 9. Module 4 — Log Analyzer

### What It Does

Upload any log file and AI will parse it, apply detection rules, and explain what it found in plain English. A non-technical person can understand the output.

### Supported Log Types

| Log Type | File Source | What It Detects |
|----------|------------|-----------------|
| Linux auth log | `/var/log/auth.log` or `/var/log/secure` | SSH brute force, off-hours logins, new user creation |
| Apache access log | `/var/log/apache2/access.log` | Web attacks, path traversal, suspicious URLs |
| Nginx access log | `/var/log/nginx/access.log` | Same as Apache |
| Windows Security | Exported .csv from Event Viewer | Login events, privilege changes |
| Generic | Any text log | IP extraction + AI analysis |

### How to Use It

1. Click **Log Analyzer** in the sidebar
2. **Drag and drop** your log file onto the upload area, or click to browse
3. Accepted formats: `.log`, `.txt`, `.csv` (max 50MB)
4. Wait for analysis (10–30 seconds depending on file size):
   - Detecting log format...
   - Parsing entries...
   - Checking IPs against threat feeds...
   - Running detection rules...
   - AI analyzing...

### Detection Rules

Five rules run automatically on every log:

**Rule 1 — Brute Force Detection**
- Triggers: Same IP makes 10+ failed login attempts within 5 minutes
- Severity: Medium (10–49 attempts) or High (50+ attempts)
- Action: Block the IP at your firewall

**Rule 2 — Off-Hours Login**
- Triggers: Successful login outside 6am–7pm
- Severity: Medium
- Action: Contact the user to verify it was authorized

**Rule 3 — New User / Privilege Escalation**
- Triggers: New account created or user added to sudo/admin group
- Severity: High
- Action: Verify this was an authorized IT action

**Rule 4 — Suspicious URL Patterns**
- Triggers: Requests containing `../`, `etc/passwd`, `.php?cmd=`, `eval(`, `/wp-admin`, `/phpmyadmin`, `union select`, `<script`
- Severity: Medium to High
- Action: Review the full request log, check if attack was successful

**Rule 5 — Multiple Source IPs for Same Account**
- Triggers: Same username logged in from 3+ different IPs within the analysis period
- Severity: High
- Action: May indicate compromised credentials — verify with the user and reset password

### Reading the Results

**Stats Bar** — Quick overview:
- Total entries parsed
- Number of unique IP addresses
- Error rate (4xx/5xx responses for web logs)
- Log type detected

**AI Summary** — Plain English overview of what the logs show. Written for a business owner, not a security analyst.

**Top Concerns** — The 2–3 most important things that need attention, in priority order.

**Recommended Actions** — Specific steps to take based on what was found.

**Rule Findings** — Each triggered detection rule with:
- Severity badge
- Description of what was found
- Affected IPs
- Specific recommendation
- "Create Incident from this Finding" button — pre-fills a new incident report

**TI-Flagged IPs** — Any IP in your logs that matches threat feeds. This is particularly valuable — it tells you if a known malicious IP has been communicating with your systems.

### Create Incident from Log Finding

If the Log Analyzer finds something serious, click **"Create Incident from this Finding"** under the finding. This takes you to the New Incident form pre-filled with the finding details, which then generates an AI playbook for it.

---

## 10. Module 5 — Playbook Library

### What It Does

A library of step-by-step incident response playbooks. Ten are pre-built and ready to use. You can also create custom playbooks for your specific environment.

### The 10 Built-In Playbooks

| Incident Type | Key Features |
|--------------|-------------|
| **Ransomware** | Includes: free decryptor check (NoMoreRansom.org), ID Ransomware identification, backup verification steps |
| **Phishing** | Includes: email header analysis, auto-forwarding rule check, mass notification to other staff |
| **Account Takeover** | Includes: session termination, OAuth revocation, impossible travel analysis |
| **Data Breach** | Includes: breach scope calculation, customer notification drafting, breach notification timeline |
| **Insider Threat** | Includes: evidence preservation sequence, HR/Legal coordination, access revocation timing |
| **DDoS Attack** | Includes: ISP escalation steps, Cloudflare activation, attack characterization |
| **Social Engineering** | Includes: wire transfer recall (URGENT), BEC fraud response, bank fraud team contacts |
| **Lost/Stolen Device** | Includes: remote wipe steps (MDM), IMEI blacklisting with PTA, device encryption check |
| **Vendor/Third-Party Breach** | Includes: credential rotation, API key revocation, vendor security questionnaire |
| **Malware Infection** | Includes: malware identification via VirusTotal, C2 domain blocking, free removal tool links |

All playbooks include **Pakistan-specific steps**: FIA contact details, PECA 2016 obligations, SBP/PTA reporting where applicable.

### Creating Custom Playbooks

1. Click **+ Create Custom Playbook**
2. Enter name, incident type, and description
3. A skeleton JSON structure is created — you can edit the content via the API or directly in the JSON field
4. Custom playbooks appear in the library alongside built-in ones (marked differently)

### Applying a Playbook to an Incident

1. Open the playbook you want
2. Click **Apply to Incident**
3. Select the incident — this replaces the AI-generated playbook with this specific one
4. Useful when you want the standardized playbook instead of the AI-generated one

---

## 11. Module 6 — Evidence Vault

### What It Does

Secure, structured storage for all evidence related to a security incident. Every file is integrity-hashed (SHA-256) on upload. Every access is logged in a chain of custody. Supports generating FIA-ready PDF reports.

### Accessing the Evidence Vault

1. Open any incident
2. Click the **Evidence** tab
3. Upload files, view stored evidence, download the FIA report

### What to Upload as Evidence

- Screenshots of ransom notes or suspicious activity
- Exported email files (.eml, .msg) of phishing emails with full headers
- Log files related to the incident
- Chat logs or WhatsApp screenshots of suspicious messages
- Bank transfer confirmations (for financial fraud)
- Any other documentation that proves what happened

### Evidence Integrity (SHA-256)

When you upload a file, SENTINEL calculates its SHA-256 cryptographic hash and stores it. This proves the file has not been modified since upload — essential for FIA/court admissibility.

Example: If you upload a log file and its hash is `a1b2c3d4...`, you can prove to FIA or a court that the file they receive is identical to what you captured at the time of the incident.

### Chain of Custody

Every file access is logged automatically:
- **Uploaded** — who uploaded it, when
- **Accessed** — who downloaded it, when
- **Deleted** — who deleted it, when (with file hash preserved)

This creates a legally defensible chain of custody.

### Generating the FIA Report (PDF)

Click **📄 FIA Report** on the incident detail page. A PDF is generated containing:

1. **Incident Summary** — title, type, severity, dates, reporter
2. **Description** — what happened in your own words
3. **Timeline** — every action taken, chronologically
4. **Indicators of Compromise** — all IOCs with their TI verdicts
5. **Evidence** — list of all files with SHA-256 hashes and upload times
6. **PECA 2016 Obligations** — whether reporting is required and who to contact
7. **MITRE ATT&CK** — which attacker techniques were identified
8. **FIA Contact Information** — ready to submit

This PDF is designed to be submitted directly to FIA Cybercrime Wing at **report.fia.gov.pk**.

---

## 12. Module 7 — Dashboard

### What It Does

Real-time overview of your organization's security posture. Gives management a single-screen view of the current threat landscape.

### Risk Score

The large circular gauge (0–100) represents your current risk level:

| Score | Level | What It Means |
|-------|-------|--------------|
| 0–25 | 🟢 Low | No significant open incidents |
| 26–50 | 🟡 Medium | Some open incidents requiring attention |
| 51–75 | 🟠 High | Serious open incidents or multiple threats |
| 76–100 | 🔴 Critical | Critical incidents open or PECA obligations pending |

**How the score is calculated:**
- +40 points for each Critical open incident
- +20 points for each High open incident
- +10 points for each Medium open incident
- +5 points for each Low open incident
- +15 bonus if any PECA-reportable incident is unresolved
- Maximum: 100

### Dashboard Panels

**Stat Cards:**
- Open Incidents (with critical count)
- Active IOCs (with malicious count)
- TI Checks Today
- PECA Actions Needed

**Incidents Per Month** — Bar chart of incident volume over the last 6 months. Trend visibility.

**Open Incidents by Severity** — Pie chart. If you see too much red and orange, something needs attention.

**Recent Incidents** — Last 5 incidents with severity and status. Click to go to the incident.

**Recent TI Checks** — Last 5 indicator checks with verdicts.

**Quick Action Buttons:**
- Report Incident → takes you to new incident form
- Check Indicator → takes you to Threat Intel
- Upload Logs → takes you to Log Analyzer

---

## 13. Settings & Configuration

### Accessing Settings

Click **⚙️ Settings** in the sidebar.

### API Keys Section

Enter your threat intelligence API keys here. They're saved to the `.env` file on the server. Keys are masked after saving (shows first 4 and last 4 characters only).

### Email Notifications

Configure to receive alerts when:
- A **Critical severity** incident is logged
- An incident requires **PECA 2016 reporting**

**Gmail Setup:**
1. Your Gmail account → Security → 2-Step Verification (enable if not already)
2. Security → App Passwords → Generate new app password
3. Use that 16-character password as `SMTP_PASSWORD` (not your normal Gmail password)
4. SMTP Host: `smtp.gmail.com`, Port: `587`

**Test Email:**
Click **📧 Send Test Email** after configuring SMTP settings.

### Organization Profile

- **Organization Name** — appears in PDF reports
- **Organization Type** — helps AI tailor responses (SME, Clinic, School, Fintech, etc.)

---

## 14. Technical Methodology

### 14.1 Threat Intelligence Pipeline

```
User submits indicator (e.g. IP: 185.220.101.45)
              ↓
      Type detection (regex)
        → Is it an IP? Domain? Hash? URL? Email?
              ↓
      Cache check (SQLite)
        → Was this checked in the last 24 hours?
        → YES: return cached result immediately
        → NO: continue
              ↓
      Parallel feed queries (asyncio.gather)
        → ALL feeds queried simultaneously
        → 7 feeds × 3 seconds = 30s sequential
        → asyncio: all 7 in ~4 seconds
              ↓
      Results aggregation
        → Which feeds flagged it?
        → What did each feed say?
              ↓
      Claude AI verdict generation
        → Feed results sent to Claude claude-sonnet-4-6
        → Returns: verdict, confidence, summary, action
              ↓
      Save to cache (24hr TTL)
              ↓
      Auto-IOC creation (if malicious/suspicious)
              ↓
      Return full result to frontend
```

**Why asyncio parallel fetching matters:**
Sequential: 7 feeds × average 3 seconds = 21 seconds
Parallel: All 7 simultaneously = ~4–6 seconds
This is the difference between a useful tool and one people abandon.

### 14.2 Feed Selection by Indicator Type

Not all feeds check all indicator types. SENTINEL selects the right feeds:

| Indicator Type | Feeds Used |
|----------------|-----------|
| IP Address | AbuseIPDB, VirusTotal, OTX, ThreatFox, IPinfo |
| Domain | VirusTotal, OTX, ThreatFox, URLhaus |
| URL | VirusTotal, URLhaus, ThreatFox |
| File Hash | VirusTotal, MalwareBazaar, OTX, ThreatFox |
| Email | VirusTotal (domain part), URLhaus (domain), OTX, ThreatFox |

### 14.3 AI Classification Methodology

When an incident is submitted, Claude receives the incident description and returns structured JSON:

```json
{
  "incident_type": "ransomware",
  "severity": "critical",
  "severity_reason": "Multiple systems affected, data encrypted, business operations halted",
  "affected_data_types": ["financial", "PII"],
  "iocs_extracted": ["185.220.101.45", "support@micros0ft-helpdesk.com"],
  "peca_reporting_required": true,
  "peca_reason": "PECA 2016 Section 9: Damage to information system — mandatory FIA reporting",
  "initial_containment": [
    "Immediately disconnect all affected machines from the network",
    "Do NOT pay the ransom without consulting FIA",
    "Photograph all ransom notes on screen as evidence"
  ]
}
```

The model `claude-sonnet-4-6` is used because:
- It reliably returns valid JSON without hallucinating structure
- It has strong security domain knowledge
- It understands Pakistan-specific regulatory context
- It balances speed and quality for this use case

### 14.4 Playbook Generation Methodology

After classification, a second Claude call generates the full playbook. The prompt provides:
- Incident type and severity
- Full incident description
- Affected systems
- Organization context (Pakistan SME)

Claude returns a 5-phase JSON structure. The prompt explicitly instructs:
- Target audience: non-technical small business owner
- Language: plain, specific, actionable
- Pakistan context: include FIA, PECA, SBP, PTA where relevant
- Role assignments: who does each step (IT/Management/HR/Legal)
- Time estimates: realistic for an SME without dedicated IT team

### 14.5 IOC Extraction Methodology

Two-stage extraction:

**Stage 1 — Regex (fast, always runs):**
```python
IP:     r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
URLs:   r'https?://[^\s"\'<>]+'
Emails: r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
MD5:    r'\b[a-fA-F0-9]{32}\b'
SHA1:   r'\b[a-fA-F0-9]{40}\b'
SHA256: r'\b[a-fA-F0-9]{64}\b'
Domain: r'\b(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}\b'
```

**Stage 2 — Claude AI (catches what regex misses):**
- Obfuscated IOCs (e.g., `185[.]220[.]101[.]45`)
- IOCs embedded in narrative text
- IOCs without obvious format patterns
- Deduplication between regex and AI results

### 14.6 Log Detection Rules

Rules implemented in `rules.py`:

```
BRUTE FORCE:
  Group failed logins by source_ip
  If same IP has >10 failures in 5 minutes → FINDING
  Severity: High if >50 attempts, Medium if 10-50

OFF-HOURS:
  For each successful login
  If hour not in [6,7...18] → FINDING
  Severity: Medium always

NEW ADMIN:
  Scan for: "new user", "useradd", "usermod.*sudo"
  Severity: High always

SUSPICIOUS URL:
  Scan for: "../", "etc/passwd", ".php?cmd=", "eval(", etc.
  Severity: High if >10 occurrences, Medium otherwise

MULTIPLE SOURCES:
  Group successful logins by username
  If same username from >3 different IPs → FINDING
  Severity: High always
```

### 14.7 PDF Report Generation

Built with **ReportLab** (pure Python, no external services):

1. Incident summary table (severity color-coded)
2. Full description text
3. Timeline table (all actions chronologically)
4. IOC table with TI verdicts
5. Evidence table with SHA-256 hashes
6. PECA 2016 section (conditional on `peca_required`)
7. MITRE ATT&CK techniques (if mapped)
8. Footer with organization name and timestamp

The PDF is formatted to be legible and professional enough to submit to FIA or a court.

### 14.8 STIX 2.1 Export

IOCs are exported as a STIX 2.1 Bundle with Indicator objects:

```json
{
  "type": "bundle",
  "spec_version": "2.1",
  "objects": [
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--{uuid}",
      "pattern": "[ipv4-addr:value = '185.220.101.45']",
      "pattern_type": "stix",
      "indicator_types": ["malicious-activity"],
      "confidence": 95
    }
  ]
}
```

STIX patterns by type:
- IP: `[ipv4-addr:value = 'x.x.x.x']`
- Domain: `[domain-name:value = 'example.com']`
- Hash: `[file:hashes.'SHA-256' = 'abc...']`
- URL: `[url:value = 'https://...']`

---

## 15. Pakistan-Specific Features

### PECA 2016 Detection

The Prevention of Electronic Crimes Act 2016 governs cybercrime in Pakistan. SENTINEL automatically determines when reporting is legally required:

| Incident Type | PECA Section | Obligation |
|--------------|-------------|------------|
| Unauthorized access | Section 3 | Reportable |
| Data breach | Section 14 | Reportable if PII involved |
| Ransomware | Section 9 | Reportable (damage to system) |
| BEC / Financial fraud | Section 10 | Reportable |
| Social engineering | Section 10 | Reportable if loss occurred |
| DDoS | Section 7 | Reportable (cyber terrorism) |

When PECA reporting is required, SENTINEL:
1. Shows a prominent orange alert on the incident detail page
2. Sends an email alert (if configured)
3. Includes FIA contact details in the playbook
4. Includes a dedicated PECA section in the PDF report

### FIA Cybercrime Wing Contact (Always Shown When Relevant)

```
Website:  report.fia.gov.pk
Helpline: 0800-02345 (free call)
Email:    cybercrime@fia.gov.pk
Physical: FIA Cybercrime headquarters, Islamabad
```

### Sector-Specific Reporting

**Financial sector (banks, fintechs, payment processors):**
- SBP Payment Systems Department notification
- Bank fraud teams (HBL: 111-111-425, MCB: 111-000-622, UBL: 111-825-888)

**Telecom:**
- PTA Cybersecurity Cell: cybersecurity@pta.gov.pk

**Health:**
- Punjab Health Department cybersecurity guidelines referenced

**Device theft:**
- PTA IMEI blacklisting: www.pta.gov.pk

### Pakistan Bank Emergency Numbers (in Social Engineering Playbook)

```
HBL:  111-111-425
MCB:  111-000-622
UBL:  111-825-888
```

For wire transfer recall after CEO fraud — time-critical, usually 24–48 hour window.

---

## 16. Common Scenarios — Step by Step

### Scenario A: Employee Reports a Suspicious Email

**Situation:** Employee says they received an email from `support@micros0ft-verify.com` with a link they almost clicked.

1. **Threat Intel** → check the domain `micros0ft-verify.com`
   - Expected result: MALICIOUS (typosquatted domain)
2. **Threat Intel** → check the link URL
   - Gets VirusTotal + URLhaus verdict
3. **Incidents** → Report New Incident
   - Title: "Phishing email targeting accounts staff"
   - Description: Include the email address, the URL, what the email said
   - AI will extract the IOCs and check them automatically
4. On incident detail:
   - Follow the **Phishing** playbook — check for auto-forwarding rules, warn other staff
   - Upload the email as evidence (use "Save As" in Outlook to save as .msg or .eml)
   - Check if PECA reporting is required
5. **Generate FIA Report** if needed

**Time from detection to plan: ~3 minutes**

---

### Scenario B: Ransomware Hits Accounts PC

**Situation:** 9am Monday. Staff member calls in panic — their computer shows a ransom note and files have `.locked` extension.

1. **Immediately** — Tell them:
   - Unplug the ethernet cable
   - Disable WiFi
   - Do NOT shut down (yet)
   - Take photos of the screen with their phone

2. **Incidents** → Report New Incident (you can do this from your own device)
   - Title: "Ransomware infection — accounts-PC"
   - Description: Describe everything. Include file extension, any email from yesterday, any USB drives used
   - Affected Systems: accounts-PC, any shared drives

3. **Incident Detail Page:**
   - Red CRITICAL badge appears
   - AI identifies it as ransomware, severity CRITICAL
   - Check if PECA required (it usually is) — orange box shows FIA contact
   - Go to **Playbook** tab → **Immediate Containment** phase
   - Work through the steps (check off as you go)
   - Step 2: "Do NOT pay ransom" — confirm with management first

4. **Playbook → Investigation:**
   - ID Ransomware site helps identify the variant
   - Check backups — when was the last clean one?
   - Note: The playbook step has the NoMoreRansom.org link for free decryptors

5. **Evidence tab:**
   - Upload the phone photos of the ransom note
   - Upload any relevant email files

6. **FIA Report** → Download and submit to report.fia.gov.pk

**PECA 2016 window: Report within 24 hours of detection**

---

### Scenario C: Weekly Security Review

**Situation:** Every Monday morning, IT person does a security check.

1. **Dashboard** → Check the risk score. Has it changed?
   - Any new incidents logged over the weekend?
   - Any PECA alerts outstanding?

2. **IOC Tracker** → Click **Bulk Re-Check**
   - Updates all Active IOCs — some may have been newly reported to feeds
   - Change status of any that have been blocked or resolved

3. **Log Analyzer** → Upload the week's auth log from your server
   - Check for brute force attempts
   - Check for off-hours logins
   - Any TI-flagged IPs in the log?

4. **Incidents** → Review open incidents
   - Any that have been sitting at "New" status too long?
   - Move them forward or escalate

**Time: 15–20 minutes**

---

### Scenario D: Checking a Suspicious File

**Situation:** Finance received an email with an invoice attachment. Not sure if it's safe.

1. **Do NOT open the file on your work computer**

2. Calculate the file's SHA-256 hash:
   - Windows: `Get-FileHash filename.pdf` in PowerShell
   - Or use online tool: **VirusTotal** (can upload directly, no SENTINEL needed for this)

3. **Threat Intel** → paste the SHA-256 hash
   - If MALICIOUS: Do not open. Log a phishing incident.
   - If CLEAN: Still be cautious — new malware may not be in databases yet

4. Alternatively, if you have VirusTotal key configured:
   - The SENTINEL TI check will run the hash through VirusTotal + MalwareBazaar + OTX + ThreatFox simultaneously

---

## 17. API Reference

The backend exposes a full REST API at `http://localhost:8000/api/`. Interactive docs at `http://localhost:8000/docs`.

### Threat Intelligence

```
POST /api/ti/check
  Body: { "indicator": "string", "indicator_type": "ip|domain|url|hash|email" }
  Returns: verdict, ai_summary, ai_action, feed_results, flagged_by

POST /api/ti/bulk-check
  Body: { "indicators": [{"value": "x", "type": "ip"}] }
  Max 50 indicators per request

GET  /api/ti/history
  Returns: last 50 TI checks

GET  /api/ti/detect-type?indicator=8.8.8.8
  Returns: detected type
```

### Incidents

```
POST /api/incidents
  Body: { title, description, affected_systems, reporter_name, reporter_email }
  Returns: full incident with playbook, classification, IOCs

GET  /api/incidents
  Query: ?status=new&severity=critical
  Returns: incident list

GET  /api/incidents/{id}
  Returns: full incident with IOCs

PATCH /api/incidents/{id}/status
  Body: { "status": "investigating" }

POST /api/incidents/{id}/timeline
  Body: { action, detail, created_by }

GET  /api/incidents/{id}/timeline
```

### IOCs

```
GET  /api/iocs
  Query: ?verdict=malicious&status=active

POST /api/iocs
  Body: { indicator, indicator_type, severity, notes }

PATCH /api/iocs/{id}
  Body: { status, severity, notes, verdict }

DELETE /api/iocs/{id}

POST /api/iocs/bulk-check

GET  /api/iocs/export/stix
  Returns: STIX 2.1 JSON bundle download

GET  /api/iocs/stats
```

### Logs

```
POST /api/logs/analyze
  Body: multipart/form-data with file field
  Returns: log_type, findings, ti_flags, ai_analysis, stats
```

### Evidence & Reports

```
POST /api/incidents/{id}/evidence
  Body: multipart/form-data with file, description, uploaded_by

GET  /api/incidents/{id}/evidence

GET  /api/evidence/{id}/download
  Query: ?accessed_by=username

DELETE /api/evidence/{id}

GET  /api/incidents/{id}/report/pdf
  Returns: PDF download
```

### Playbooks

```
GET  /api/playbooks
GET  /api/playbooks/{id}
POST /api/playbooks
PUT  /api/playbooks/{id}    (custom only)
DELETE /api/playbooks/{id}  (custom only)
POST /api/playbooks/{id}/apply/{incident_id}
```

### Dashboard & Settings

```
GET  /api/dashboard/stats
GET  /api/settings
POST /api/settings
POST /api/settings/test-email
GET  /api/health
```

---

## 18. Troubleshooting

### Backend won't start

**Error: `ModuleNotFoundError`**
```bash
# Make sure venv is activated
venv\Scripts\activate
pip install -r requirements.txt
```

**Error: `Address already in use`**
```bash
# Port 8000 is taken — use a different port
uvicorn main:app --reload --port 8001
# Then update vite.config.ts proxy target to :8001
```

### "API key not configured" in TI results

The TI feeds that show this error don't have their key set. Go to Settings and add the key. Feeds without keys are skipped — you still get results from the others.

### AI verdict shows "No AI analysis available"

Your `ANTHROPIC_API_KEY` is not set or is invalid. Check Settings → API Keys. The key starts with `sk-ant-api03-`.

### Frontend shows "Failed to load" or blank dashboard

Make sure the backend is running at port 8000. The frontend proxies all `/api/` calls to `http://localhost:8000`. Check your terminal running `uvicorn main:app --reload`.

### Email test fails

For Gmail: you need an **App Password**, not your regular Gmail password. Regular Gmail password will fail even if it's correct — Google blocks direct SMTP login without App Passwords.

Steps:
1. Google Account → Security → 2-Step Verification (enable)
2. Google Account → Security → App Passwords
3. Select app: Mail, device: Windows computer
4. Copy the 16-character password
5. Use this as `SMTP_PASSWORD` in Settings

### TI check takes more than 30 seconds

One or more feeds is timing out. This usually means:
- AbuseIPDB or VirusTotal API key is invalid (they fail slowly)
- Network connectivity issues to one of the feeds
- Each feed has a 10–15 second timeout, so worst case is ~15s

Check the feed results table — the failing feed will show "Error: ..."

### Log analyzer shows "no entries parsed"

The log file format wasn't recognized. Try:
- Ensure the file is plain text (not binary)
- If it's a Windows Event Log, export as CSV from Event Viewer first: Event Viewer → Action → Save All Events As → CSV
- The generic parser will handle any text file and extract IPs

---

## 19. Portfolio Context

### Project Background

SENTINEL was built as a portfolio capstone project demonstrating **blue team** (defensive) security capability, specifically:

- **GRC alignment** — PECA 2016 compliance, evidence chain of custody, regulatory reporting
- **Threat Intelligence** — practical integration of multiple free feeds with aggregated AI verdict
- **Incident Response** — full NIST IR framework: Prepare → Detect → Analyze → Contain → Eradicate → Recover
- **AI Security Applications** — production-grade use of LLMs for security analysis, not just demos

### Skills Demonstrated

| Skill Area | Evidence |
|-----------|---------|
| Python backend | FastAPI, asyncio, SQLAlchemy, ReportLab |
| Security concepts | TI feeds, IOCs, STIX 2.1, MITRE ATT&CK, PECA 2016, chain of custody |
| AI integration | Anthropic Claude API, structured output, prompt engineering for security |
| Frontend | React 18, TypeScript, Tailwind, Recharts |
| Databases | SQLite schema design, TTL caching, relational models |
| Pakistan context | FIA, PECA 2016, SBP, PTA — real regulatory knowledge |

### Sprint Methodology

The project was built in 5 sprints following the SRS document:

| Sprint | Focus | Weeks |
|--------|-------|-------|
| 1 | Project structure + Threat Intelligence Engine | 1–2 |
| 2 | Incident Manager (AI classifier + playbook + IOC extractor) | 3–4 |
| 3 | IOC Tracker + Log Analyzer | 5–6 |
| 4 | Playbook Library + Evidence Vault + PDF reports | 7–8 |
| 5 | Dashboard + Notifications + Polish | 9–10 |

Each sprint builds on the previous — the database schema and module structure support all features from day one.

---

*SENTINEL — Giving Pakistani small businesses a fighting chance.*

*Prepared by: Manahil Khan | v1.0 | June 2026*
