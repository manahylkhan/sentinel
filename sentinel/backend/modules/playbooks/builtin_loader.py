import json

BUILTIN_PLAYBOOKS = [
    {
        "name": "Ransomware Response",
        "incident_type": "ransomware",
        "description": "Complete response playbook for ransomware infection incidents",
        "phases": [
            {"phase_name": "Immediate Containment", "time_target": "Within 30 minutes", "steps": [
                {"step_number": 1, "action": "IMMEDIATELY disconnect all affected computers from the network", "owner": "IT Person", "time_estimate": "5 minutes", "critical": True, "details": "Unplug ethernet cables and disable WiFi on infected machines. Do NOT shut them down yet — evidence may be lost."},
                {"step_number": 2, "action": "Do NOT pay the ransom without consulting legal/management", "owner": "Management", "time_estimate": "Immediate", "critical": True, "details": "Payment does not guarantee recovery and funds criminal activity. Consult FIA before any payment decision."},
                {"step_number": 3, "action": "Photograph ransom notes and encrypted file listings", "owner": "IT Person", "time_estimate": "10 minutes", "critical": True, "details": "Use your mobile phone to photograph all ransom notes on screen. Note the file extension of encrypted files (e.g., .locked, .encrypted)."},
                {"step_number": 4, "action": "Identify all affected systems and shared drives", "owner": "IT Person", "time_estimate": "15 minutes", "critical": True, "details": "Check all computers and shared network drives for encrypted files."},
                {"step_number": 5, "action": "Contact management and initiate incident response", "owner": "IT Person", "time_estimate": "5 minutes", "critical": True, "details": "Notify management immediately. Activate this playbook."},
            ]},
            {"phase_name": "Investigation", "time_target": "Within 4 hours", "steps": [
                {"step_number": 1, "action": "Identify ransomware variant using ID Ransomware", "owner": "IT Person", "time_estimate": "30 minutes", "critical": True, "details": "Upload a ransom note or encrypted file to id-ransomware.malwarehunterteam.com — identifies the variant and whether a free decryptor exists."},
                {"step_number": 2, "action": "Determine infection vector — how did it get in?", "owner": "IT Person", "time_estimate": "1 hour", "critical": True, "details": "Check email logs for suspicious attachments, browsing history, RDP logs, USB drives used recently."},
                {"step_number": 3, "action": "Check backup integrity — when was last clean backup?", "owner": "IT Person", "time_estimate": "30 minutes", "critical": True, "details": "Identify the most recent unaffected backup. Determine if backups are also encrypted."},
                {"step_number": 4, "action": "Collect forensic evidence before remediation", "owner": "IT Person", "time_estimate": "1 hour", "critical": False, "details": "Create disk images if possible. Export Windows Event Logs. Document all affected files."},
            ]},
            {"phase_name": "Eradication", "time_target": "Within 24 hours", "steps": [
                {"step_number": 1, "action": "Check for free decryptors at NoMoreRansom.org", "owner": "IT Person", "time_estimate": "30 minutes", "critical": True, "details": "Many ransomware families have free decryptors. Check nomoreransom.org before doing anything destructive."},
                {"step_number": 2, "action": "Reformat and reinstall operating system on infected machines", "owner": "IT Person", "time_estimate": "4-8 hours", "critical": True, "details": "Wipe affected drives and reinstall OS. Do not attempt to clean — ransomware leaves backdoors."},
                {"step_number": 3, "action": "Patch all systems and close the attack vector", "owner": "IT Person", "time_estimate": "2 hours", "critical": True, "details": "Apply all Windows/software updates. If RDP was the vector: disable it or move to VPN. If phishing: retrain staff."},
            ]},
            {"phase_name": "Recovery", "time_target": "Within 72 hours", "steps": [
                {"step_number": 1, "action": "Restore data from verified clean backups", "owner": "IT Person", "time_estimate": "Varies", "critical": True, "details": "Restore from backups taken BEFORE the infection date. Verify restored files are not encrypted."},
                {"step_number": 2, "action": "Change ALL passwords across the organization", "owner": "All Staff + IT", "time_estimate": "2 hours", "critical": True, "details": "Ransomware attackers often steal credentials. Change: Windows login, email, banking, cloud services, VPN."},
                {"step_number": 3, "action": "Enable MFA on all critical systems", "owner": "IT Person", "time_estimate": "2 hours", "critical": True, "details": "Enable two-factor authentication on email, banking, and remote access immediately."},
                {"step_number": 4, "action": "Test all restored systems before reconnecting to network", "owner": "IT Person", "time_estimate": "1 hour", "critical": True, "details": "Verify clean state before reconnecting — one missed infected machine can re-encrypt everything."},
            ]},
            {"phase_name": "Lessons Learned", "time_target": "Within 1 week", "steps": [
                {"step_number": 1, "action": "Conduct post-incident review meeting", "owner": "Management + IT", "time_estimate": "1 hour", "critical": False, "details": "Document what happened, what worked, what failed, and what to improve."},
                {"step_number": 2, "action": "Implement offline/immutable backup solution", "owner": "IT Person", "time_estimate": "1-2 days", "critical": True, "details": "3-2-1 backup rule: 3 copies, 2 different media, 1 offsite. Ensure backups cannot be encrypted by ransomware."},
                {"step_number": 3, "action": "Train all staff on phishing awareness", "owner": "Management", "time_estimate": "2 hours", "critical": False, "details": "Most ransomware arrives via phishing email. Train staff to identify suspicious emails."},
            ]},
        ],
        "notify_list": [
            {"who": "CEO/Owner", "why": "Executive decision-making authority, especially re: ransom payment", "when": "Immediately", "template_hint": "We have detected a ransomware infection affecting [X systems]. Data is encrypted. We are activating the incident response plan."},
            {"who": "All Staff", "why": "Stop using computers — prevent spread", "when": "Within 1 hour", "template_hint": "URGENT: Please stop using your computers immediately and unplug them from the network. Do not open any files. IT will advise when safe to continue."},
            {"who": "Cyber Insurance Provider", "why": "Policy may cover ransomware response costs", "when": "Within 4 hours", "template_hint": "We have experienced a ransomware incident. Calling to file a claim and get guidance."},
        ],
        "pakistan_specific": [
            "Report to FIA Cybercrime Wing: report.fia.gov.pk | 0800-02345 | cybercrime@fia.gov.pk",
            "PECA 2016 Section 9: Ransomware constitutes unauthorized access and data damage — reportable offense",
            "SBP regulated entities must report to SBP within 3 hours of detection",
            "Preserve all encrypted files and ransom notes as evidence for FIA",
            "Do NOT pay ransom without consulting FIA — payment may violate anti-money laundering laws",
        ],
        "tools_needed": ["ID Ransomware (id-ransomware.malwarehunterteam.com)", "NoMoreRansom.org (free decryptors)", "Clean USB drive for bootable OS", "Backup media", "Windows USB installer"],
    },
    {
        "name": "Phishing Attack Response",
        "incident_type": "phishing",
        "description": "Response playbook when an employee receives or clicks a phishing email",
        "phases": [
            {"phase_name": "Immediate Containment", "time_target": "Within 1 hour", "steps": [
                {"step_number": 1, "action": "Isolate the affected user's machine if they clicked a link/opened attachment", "owner": "IT Person", "time_estimate": "5 minutes", "critical": True, "details": "If they clicked: disconnect from network. If they only received but didn't click: no isolation needed."},
                {"step_number": 2, "action": "Immediately reset the affected user's email password", "owner": "IT Person", "time_estimate": "5 minutes", "critical": True, "details": "If credentials were entered on a phishing page, the account may already be compromised."},
                {"step_number": 3, "action": "Enable MFA on the affected account if not already enabled", "owner": "IT Person", "time_estimate": "5 minutes", "critical": True, "details": "This prevents access even if password was stolen."},
                {"step_number": 4, "action": "Block the phishing sender domain/IP at email gateway", "owner": "IT Person", "time_estimate": "10 minutes", "critical": True, "details": "Add to email blacklist. Check if other employees received the same email."},
                {"step_number": 5, "action": "Preserve the phishing email — DO NOT delete it", "owner": "IT Person", "time_estimate": "5 minutes", "critical": True, "details": "Export the email with full headers. This is evidence for FIA reporting."},
            ]},
            {"phase_name": "Investigation", "time_target": "Within 4 hours", "steps": [
                {"step_number": 1, "action": "Check email logs — who else received this phishing email?", "owner": "IT Person", "time_estimate": "30 minutes", "critical": True, "details": "Search email logs for the same sender, subject, or links. Notify all recipients."},
                {"step_number": 2, "action": "Analyze the phishing email headers and links", "owner": "IT Person", "time_estimate": "30 minutes", "critical": False, "details": "Check sender IP, spoofed domain registration date, phishing URL destination. Use MX Toolbox and VirusTotal."},
                {"step_number": 3, "action": "Check affected user's account for unauthorized activity", "owner": "IT Person", "time_estimate": "30 minutes", "critical": True, "details": "Review email sent folder (auto-forwarding rules), login history, any emails read or deleted."},
                {"step_number": 4, "action": "Check for malware if user clicked the link", "owner": "IT Person", "time_estimate": "1 hour", "critical": True, "details": "Run full antivirus scan on affected machine. Check for new browser extensions, startup entries, or scheduled tasks."},
            ]},
            {"phase_name": "Eradication", "time_target": "Within 24 hours", "steps": [
                {"step_number": 1, "action": "Remove any malware found during investigation", "owner": "IT Person", "time_estimate": "Varies", "critical": True, "details": "Use reputable AV tools. If severe infection, reformat the machine."},
                {"step_number": 2, "action": "Remove any malicious email forwarding rules", "owner": "IT Person", "time_estimate": "15 minutes", "critical": True, "details": "Check for auto-forward rules in Outlook/Gmail settings that send emails to external addresses."},
                {"step_number": 3, "action": "Scan all shared drives for malware spread", "owner": "IT Person", "time_estimate": "1 hour", "critical": False, "details": "If machine was infected, check network drives it had access to."},
            ]},
            {"phase_name": "Recovery", "time_target": "Within 48 hours", "steps": [
                {"step_number": 1, "action": "Restore affected systems from clean backup if needed", "owner": "IT Person", "time_estimate": "Varies", "critical": False, "details": "Only needed if malware was found and could not be fully removed."},
                {"step_number": 2, "action": "Reset all passwords for any services accessed from affected machine", "owner": "IT Person + User", "time_estimate": "30 minutes", "critical": True, "details": "Include: email, banking, company systems, cloud services."},
                {"step_number": 3, "action": "Monitor affected accounts for 30 days for suspicious activity", "owner": "IT Person", "time_estimate": "Ongoing", "critical": True, "details": "Set up login alerts. Review weekly for unusual logins or data access."},
            ]},
            {"phase_name": "Lessons Learned", "time_target": "Within 1 week", "steps": [
                {"step_number": 1, "action": "Run phishing awareness training for all staff", "owner": "Management", "time_estimate": "2 hours", "critical": False, "details": "Use real examples. Show them what to look for. Make it a regular quarterly exercise."},
                {"step_number": 2, "action": "Enable email filtering and anti-phishing tools", "owner": "IT Person", "time_estimate": "1 day", "critical": True, "details": "Enable SPF/DKIM/DMARC records. Use Microsoft Defender for O365 or Google Workspace protection."},
            ]},
        ],
        "notify_list": [
            {"who": "Management", "why": "Awareness and decision-making", "when": "Within 1 hour", "template_hint": "An employee received and may have interacted with a phishing email. We are investigating."},
            {"who": "All Staff", "why": "Warn others who may have received same email", "when": "Within 2 hours", "template_hint": "WARNING: Do NOT click links in recent emails from [sender]. Delete immediately and report to IT."},
        ],
        "pakistan_specific": [
            "Report to FIA Cybercrime Wing if credentials were stolen: report.fia.gov.pk | 0800-02345",
            "If customer data was accessed via compromised account: PECA 2016 Section 14 may apply",
            "Export phishing email with headers as evidence for FIA report",
            "Forward phishing email to cybercrime@fia.gov.pk for their awareness",
        ],
        "tools_needed": ["Email export tool (Outlook: File > Save As)", "VirusTotal for URL analysis", "MX Toolbox for email header analysis", "Antivirus software"],
    },
    {
        "name": "Account Takeover Response",
        "incident_type": "account_takeover",
        "description": "Response when a user account has been compromised by an unauthorized party",
        "phases": [
            {"phase_name": "Immediate Containment", "time_target": "Within 30 minutes", "steps": [
                {"step_number": 1, "action": "Immediately terminate all active sessions for the compromised account", "owner": "IT Person", "time_estimate": "5 minutes", "critical": True, "details": "In O365: Admin > Active Users > [User] > Sign out of all sessions. In Google: Admin > Users > [User] > Reset sign-in cookies."},
                {"step_number": 2, "action": "Reset the account password to a strong temporary password", "owner": "IT Person", "time_estimate": "5 minutes", "critical": True, "details": "Use 16+ character random password. Do NOT reuse old password. Force change on next login."},
                {"step_number": 3, "action": "Enable/force MFA on the compromised account", "owner": "IT Person", "time_estimate": "5 minutes", "critical": True, "details": "Without MFA, even after password reset, attacker can regain access if they have password reset capability."},
                {"step_number": 4, "action": "Revoke all OAuth tokens and app permissions for the account", "owner": "IT Person", "time_estimate": "10 minutes", "critical": True, "details": "Connected apps may maintain access even after password change. Check in account security settings."},
            ]},
            {"phase_name": "Investigation", "time_target": "Within 4 hours", "steps": [
                {"step_number": 1, "action": "Review account login history for unauthorized access timeline", "owner": "IT Person", "time_estimate": "30 minutes", "critical": True, "details": "When did unauthorized access begin? What IP addresses? What country? What was accessed?"},
                {"step_number": 2, "action": "Check what data was accessed, read, or exfiltrated", "owner": "IT Person", "time_estimate": "1 hour", "critical": True, "details": "Review audit logs: emails read, files opened, data downloaded. This determines if breach notification is needed."},
                {"step_number": 3, "action": "Identify the attack vector — how did attacker get credentials?", "owner": "IT Person", "time_estimate": "30 minutes", "critical": True, "details": "Check: phishing emails, data breach databases (HaveIBeenPwned), password reuse from other breaches."},
            ]},
            {"phase_name": "Eradication", "time_target": "Within 24 hours", "steps": [
                {"step_number": 1, "action": "Remove any malicious inbox rules, forwarding, or delegates", "owner": "IT Person", "time_estimate": "15 minutes", "critical": True, "details": "Attackers often create email forwarding rules or add delegates to maintain persistent access."},
                {"step_number": 2, "action": "Review and revoke any unauthorized OAuth application access", "owner": "IT Person", "time_estimate": "15 minutes", "critical": True, "details": "Remove any third-party apps the attacker may have authorized to access the account."},
            ]},
            {"phase_name": "Recovery", "time_target": "Within 48 hours", "steps": [
                {"step_number": 1, "action": "Restore any deleted or modified content from trash/recycle", "owner": "IT Person", "time_estimate": "Varies", "critical": False, "details": "Check email trash, deleted items. Restore what was deleted by attacker."},
                {"step_number": 2, "action": "Notify affected customers/partners if their data was exposed", "owner": "Management + Legal", "time_estimate": "Varies", "critical": True, "details": "If emails containing customer PII were accessed, breach notification may be legally required."},
            ]},
            {"phase_name": "Lessons Learned", "time_target": "Within 1 week", "steps": [
                {"step_number": 1, "action": "Enforce MFA across all accounts organization-wide", "owner": "IT + Management", "time_estimate": "1-2 days", "critical": True, "details": "90% of account takeovers are prevented by MFA. Make it mandatory for everyone."},
                {"step_number": 2, "action": "Implement password manager policy", "owner": "IT + Management", "time_estimate": "1 day", "critical": True, "details": "Prohibit password reuse. Provide staff with a password manager (Bitwarden is free)."},
            ]},
        ],
        "notify_list": [
            {"who": "Management", "why": "Business impact assessment needed", "when": "Immediately", "template_hint": "We have detected unauthorized access to [user]'s account. We have locked it and are investigating the scope."},
            {"who": "Affected User", "why": "They need to verify what was in the account and help investigation", "when": "Immediately", "template_hint": "Your account was accessed by an unauthorized person. We have secured it. Please meet with IT immediately."},
        ],
        "pakistan_specific": [
            "Report to FIA Cybercrime Wing: report.fia.gov.pk | 0800-02345",
            "PECA 2016 Section 3: Unauthorized access to information system is a criminal offense",
            "If financial accounts were compromised: report to SBP and relevant bank's fraud team immediately",
            "If customer data was exposed: PECA Section 14 (data protection) may require reporting",
        ],
        "tools_needed": ["Account audit logs", "HaveIBeenPwned.com", "Browser forensics tools if needed"],
    },
    {
        "name": "Data Breach Response",
        "incident_type": "data_breach",
        "description": "Response when sensitive customer or business data has been exfiltrated or exposed",
        "phases": [
            {"phase_name": "Immediate Containment", "time_target": "Within 1 hour", "steps": [
                {"step_number": 1, "action": "Identify and immediately close the breach vector", "owner": "IT Person", "time_estimate": "30 minutes", "critical": True, "details": "Whether it's an exposed database, compromised account, or misconfigured server — close it NOW."},
                {"step_number": 2, "action": "Preserve all logs before any system changes", "owner": "IT Person", "time_estimate": "15 minutes", "critical": True, "details": "Export database access logs, web server logs, application logs. These are critical evidence."},
                {"step_number": 3, "action": "Determine what data was accessed and how much", "owner": "IT Person", "time_estimate": "30 minutes", "critical": True, "details": "Identify: what tables/files were accessed, how many records, what data types (PII, financial, health)."},
            ]},
            {"phase_name": "Investigation", "time_target": "Within 4 hours", "steps": [
                {"step_number": 1, "action": "Identify all individuals whose data was compromised", "owner": "IT + Management", "time_estimate": "2 hours", "critical": True, "details": "This list is needed for breach notifications. Export the list of affected records."},
                {"step_number": 2, "action": "Determine how long the breach was active", "owner": "IT Person", "time_estimate": "1 hour", "critical": True, "details": "Review access logs to determine when unauthorized access began. Earlier = more data potentially taken."},
                {"step_number": 3, "action": "Engage legal counsel immediately", "owner": "Management", "time_estimate": "Same day", "critical": True, "details": "Data breach notification requirements vary. Get legal advice on PECA obligations and liability."},
            ]},
            {"phase_name": "Eradication", "time_target": "Within 24 hours", "steps": [
                {"step_number": 1, "action": "Patch or remediate the vulnerability that allowed the breach", "owner": "IT Person", "time_estimate": "Varies", "critical": True, "details": "Fix the root cause: patch software, fix SQL injection, change leaked credentials, reconfigure firewall."},
                {"step_number": 2, "action": "Reset all credentials that may have been exposed", "owner": "IT Person", "time_estimate": "1 hour", "critical": True, "details": "If any passwords, API keys, or tokens were in the breached data — rotate them all."},
            ]},
            {"phase_name": "Recovery", "time_target": "Within 72 hours", "steps": [
                {"step_number": 1, "action": "Notify affected individuals about the breach", "owner": "Management + Legal", "time_estimate": "Varies", "critical": True, "details": "Breach notification is an ethical and possibly legal obligation. Be transparent about what happened."},
                {"step_number": 2, "action": "Implement data encryption at rest if not already in place", "owner": "IT Person", "time_estimate": "Varies", "critical": True, "details": "Encrypted data breaches are less severe. Implement AES-256 encryption for all sensitive data stores."},
            ]},
            {"phase_name": "Lessons Learned", "time_target": "Within 2 weeks", "steps": [
                {"step_number": 1, "action": "Conduct security audit of all data stores and access controls", "owner": "IT + External Auditor", "time_estimate": "1 week", "critical": True, "details": "Review who has access to what data. Apply principle of least privilege."},
                {"step_number": 2, "action": "Implement Data Loss Prevention (DLP) monitoring", "owner": "IT Person", "time_estimate": "1-2 days", "critical": False, "details": "Alert on large data exports, unusual query patterns, bulk data downloads."},
            ]},
        ],
        "notify_list": [
            {"who": "Legal Counsel", "why": "Immediate legal advice on obligations", "when": "Immediately", "template_hint": "We have experienced a data breach affecting [X] customer records. Need immediate legal guidance on PECA notification requirements."},
            {"who": "Management/Board", "why": "Major business risk requiring executive decisions", "when": "Immediately", "template_hint": "URGENT: Data breach detected. Customer PII affected. Convening emergency meeting."},
            {"who": "Affected Customers", "why": "Legal/ethical notification obligation", "when": "Within 72 hours", "template_hint": "We are writing to inform you of a security incident that may have affected your personal information..."},
        ],
        "pakistan_specific": [
            "PECA 2016 Section 14: Unauthorized disclosure of personal data is illegal — report to FIA",
            "FIA Cybercrime: report.fia.gov.pk | 0800-02345 — report within 24 hours",
            "SBP regulated entities: report to SBP within 3 hours if financial data involved",
            "PTA: If telecom customer data breached, report to PTA Cybersecurity Cell",
            "Health data breaches: consult Punjab Health Department cybersecurity guidelines",
            "Consider engaging a PR firm for customer communications — reputational damage is significant",
        ],
        "tools_needed": ["Database access logs", "Legal counsel", "PR/Communications support", "Credit monitoring service for affected customers"],
    },
    {
        "name": "Insider Threat Response",
        "incident_type": "insider",
        "description": "Response when a current or former employee is suspected of malicious activity",
        "phases": [
            {"phase_name": "Immediate Containment", "time_target": "Within 2 hours", "steps": [
                {"step_number": 1, "action": "Preserve evidence BEFORE the suspect knows they are under investigation", "owner": "IT Person + Management", "time_estimate": "1 hour", "critical": True, "details": "Evidence can be destroyed if suspect is alerted. Document everything before taking any action."},
                {"step_number": 2, "action": "Quietly revoke the suspect's access without alerting them if still employed", "owner": "IT Person + HR", "time_estimate": "30 minutes", "critical": True, "details": "Coordinate with HR. Disable account but do not send any notifications to the suspect's devices."},
                {"step_number": 3, "action": "Engage HR and Legal immediately — this is an HR matter as much as IT", "owner": "Management", "time_estimate": "Immediate", "critical": True, "details": "Insider incidents require HR, Legal, and IT to work together. Do not act unilaterally."},
            ]},
            {"phase_name": "Investigation", "time_target": "Within 24 hours", "steps": [
                {"step_number": 1, "action": "Collect all audit logs of the suspect's activity", "owner": "IT Person", "time_estimate": "2 hours", "critical": True, "details": "Email logs, file access logs, system login logs, USB device history, print logs. Chain of custody is critical."},
                {"step_number": 2, "action": "Identify what data was accessed, copied, or sent externally", "owner": "IT Person", "time_estimate": "2 hours", "critical": True, "details": "Look for: large email attachments sent externally, USB copy events, cloud storage uploads (Dropbox, Google Drive)."},
            ]},
            {"phase_name": "Eradication", "time_target": "Within 48 hours", "steps": [
                {"step_number": 1, "action": "Formally terminate access across all systems upon HR authorization", "owner": "IT Person", "time_estimate": "1 hour", "critical": True, "details": "Email, VPN, physical access cards, cloud services, third-party vendor access — all systems."},
            ]},
            {"phase_name": "Recovery", "time_target": "Within 1 week", "steps": [
                {"step_number": 1, "action": "Assess and remediate any damage caused by the insider", "owner": "IT + Management", "time_estimate": "Varies", "critical": True, "details": "Restore modified/deleted files, change any shared credentials the insider knew, notify affected clients."},
            ]},
            {"phase_name": "Lessons Learned", "time_target": "Within 2 weeks", "steps": [
                {"step_number": 1, "action": "Implement offboarding checklist to revoke access on last day", "owner": "HR + IT", "time_estimate": "1 day", "critical": True, "details": "Every departing employee's access must be revoked immediately on their last day — not 'when IT has time'."},
                {"step_number": 2, "action": "Implement least-privilege access controls", "owner": "IT Person", "time_estimate": "1 week", "critical": True, "details": "Staff should only have access to systems they need for their role. Review all access quarterly."},
            ]},
        ],
        "notify_list": [
            {"who": "HR Manager", "why": "This is an HR/legal matter requiring HR leadership", "when": "Immediately", "template_hint": "We have suspected insider activity by [role]. Need to coordinate investigation while preserving evidence."},
            {"who": "Legal Counsel", "why": "Employment law, potential criminal referral", "when": "Immediately", "template_hint": "Suspected insider threat incident. Need legal guidance on investigation procedures and potential FIA referral."},
        ],
        "pakistan_specific": [
            "PECA 2016 Section 3 and 9: Unauthorized data access by insider is a criminal offense",
            "Report to FIA Cybercrime if criminal referral warranted: report.fia.gov.pk | 0800-02345",
            "Employment law in Pakistan: consult labor law attorney before termination",
            "Evidence collected must follow chain of custody for FIA/court admissibility",
        ],
        "tools_needed": ["Audit log export tools", "USB forensics software", "Email forensics tools", "HR documentation templates"],
    },
    {
        "name": "DDoS Attack Response",
        "incident_type": "ddos",
        "description": "Response when systems are experiencing a Distributed Denial of Service attack",
        "phases": [
            {"phase_name": "Immediate Containment", "time_target": "Within 30 minutes", "steps": [
                {"step_number": 1, "action": "Contact your ISP/hosting provider immediately — they can absorb the attack upstream", "owner": "IT Person", "time_estimate": "15 minutes", "critical": True, "details": "ISPs can implement null routing or blackhole traffic before it reaches your network. This is the fastest mitigation."},
                {"step_number": 2, "action": "Enable DDoS protection on hosting/cloud provider (Cloudflare, etc.)", "owner": "IT Person", "time_estimate": "15 minutes", "critical": True, "details": "If using Cloudflare: enable 'Under Attack' mode. AWS Shield, Azure DDoS Protection."},
                {"step_number": 3, "action": "Identify and block attack source IPs at firewall", "owner": "IT Person", "time_estimate": "30 minutes", "critical": False, "details": "DDoS uses many IPs but blocking the top sources reduces load. Check firewall logs for top source IPs."},
            ]},
            {"phase_name": "Investigation", "time_target": "Within 4 hours", "steps": [
                {"step_number": 1, "action": "Analyze traffic to characterize the attack", "owner": "IT Person", "time_estimate": "1 hour", "critical": True, "details": "Volume (Gbps)? Packet type (UDP/TCP/HTTP)? Source geography? Amplification attack? Application layer?"},
                {"step_number": 2, "action": "Determine if DDoS is cover for another attack", "owner": "IT Person", "time_estimate": "1 hour", "critical": True, "details": "DDoS is sometimes a distraction. Check if any systems were breached while team was focused on DDoS."},
            ]},
            {"phase_name": "Eradication", "time_target": "During attack", "steps": [
                {"step_number": 1, "action": "Implement rate limiting on web servers", "owner": "IT Person", "time_estimate": "30 minutes", "critical": True, "details": "Limit requests per IP. Block countries not relevant to your business if attack is geographically concentrated."},
                {"step_number": 2, "action": "Scale up infrastructure if using cloud hosting", "owner": "IT Person", "time_estimate": "30 minutes", "critical": False, "details": "Auto-scaling can absorb attack volume. More expensive but keeps service available."},
            ]},
            {"phase_name": "Recovery", "time_target": "Post-attack", "steps": [
                {"step_number": 1, "action": "Gradually remove blocks as attack subsides — monitor for return", "owner": "IT Person", "time_estimate": "Ongoing", "critical": True, "details": "DDoS attacks often come in waves. Keep defenses up for 48 hours after apparent end."},
            ]},
            {"phase_name": "Lessons Learned", "time_target": "Within 1 week", "steps": [
                {"step_number": 1, "action": "Implement Cloudflare or similar CDN/DDoS protection", "owner": "IT Person", "time_estimate": "1 day", "critical": True, "details": "Cloudflare free tier provides significant DDoS protection. Essential for any internet-facing service."},
                {"step_number": 2, "action": "Create DDoS runbook for faster response next time", "owner": "IT Person", "time_estimate": "2 hours", "critical": False, "details": "Document ISP contact, cloud provider contacts, escalation path. Saves critical time during next attack."},
            ]},
        ],
        "notify_list": [
            {"who": "ISP/Hosting Provider", "why": "They can mitigate upstream — fastest solution", "when": "Immediately", "template_hint": "We are experiencing a DDoS attack. Our IP is [X]. Need emergency mitigation assistance."},
            {"who": "Management", "why": "Business impact — services down means revenue loss", "when": "Immediately", "template_hint": "Our website/services are experiencing a DDoS attack. ETA for restoration is unclear. IT is working with ISP."},
        ],
        "pakistan_specific": [
            "Report to PTA Cybersecurity Cell if attack is severe: cybersecurity@pta.gov.pk",
            "Report to FIA Cybercrime Wing: report.fia.gov.pk | 0800-02345",
            "PECA 2016 Section 7: Cyber terrorism (DDoS) is a criminal offense — consider criminal referral",
            "PTCL/ISP emergency contacts: PTCL NOC: 0800-80808",
        ],
        "tools_needed": ["Cloudflare (cloudflare.com)", "ISP emergency contact", "Firewall admin access", "Traffic analyzer (Wireshark, PRTG)"],
    },
    {
        "name": "Social Engineering Response",
        "incident_type": "social_eng",
        "description": "Response to CEO fraud, vishing, pretexting, or business email compromise",
        "phases": [
            {"phase_name": "Immediate Containment", "time_target": "Within 1 hour", "steps": [
                {"step_number": 1, "action": "If a financial transfer was made — contact bank IMMEDIATELY to reverse it", "owner": "Management + Finance", "time_estimate": "URGENT", "critical": True, "details": "Banks have 24-48 hours to reverse fraudulent wire transfers. Every minute counts. Call fraud line directly."},
                {"step_number": 2, "action": "Gather all communication evidence immediately", "owner": "IT Person", "time_estimate": "15 minutes", "critical": True, "details": "Screenshot emails, save voicemails, document what was said. Do NOT delete any communication."},
                {"step_number": 3, "action": "Alert all financial approvers — no wire transfers without in-person verification", "owner": "Management", "time_estimate": "Immediate", "critical": True, "details": "Implement emergency procedure: all wire transfers >10,000 PKR require in-person or video call verification until further notice."},
            ]},
            {"phase_name": "Investigation", "time_target": "Within 4 hours", "steps": [
                {"step_number": 1, "action": "Trace the fraudulent email — identify the spoofed domain", "owner": "IT Person", "time_estimate": "30 minutes", "critical": True, "details": "Check email headers. Attackers often register domains like comp4ny.com vs company.com."},
                {"step_number": 2, "action": "Identify how attacker knew enough to be convincing", "owner": "Management + IT", "time_estimate": "1 hour", "critical": True, "details": "Was your LinkedIn public? Did they access internal email? Is this an insider? Determine intelligence source."},
            ]},
            {"phase_name": "Eradication", "time_target": "Within 24 hours", "steps": [
                {"step_number": 1, "action": "Report fraudulent domain to registrar for takedown", "owner": "IT Person", "time_estimate": "30 minutes", "critical": False, "details": "Report to domain registrar's abuse email. Also report to Google Safe Browsing, Netcraft."},
            ]},
            {"phase_name": "Recovery", "time_target": "Within 1 week", "steps": [
                {"step_number": 1, "action": "Work with bank and FIA to recover funds if transferred", "owner": "Management + Legal", "time_estimate": "Ongoing", "critical": True, "details": "File FIA complaint immediately. Banks cooperate with FIA for fraud investigations."},
            ]},
            {"phase_name": "Lessons Learned", "time_target": "Within 1 week", "steps": [
                {"step_number": 1, "action": "Implement dual authorization for all wire transfers above threshold", "owner": "Management + Finance", "time_estimate": "1 day", "critical": True, "details": "No single person should approve large transfers. Require 2 approvers and out-of-band verification."},
                {"step_number": 2, "action": "Train all finance staff on BEC (Business Email Compromise) attacks", "owner": "Management", "time_estimate": "2 hours", "critical": True, "details": "Show real examples. The CEO is never going to ask for a secret wire transfer via email."},
            ]},
        ],
        "notify_list": [
            {"who": "Bank Fraud Team", "why": "Wire transfer recall — time critical", "when": "IMMEDIATELY if transfer made", "template_hint": "We have been victim of BEC fraud. A wire transfer was made to [account] on [date]. We need emergency reversal."},
            {"who": "FIA Cybercrime", "why": "Criminal complaint and potential fund recovery", "when": "Within 4 hours", "template_hint": "We wish to file a complaint for BEC/CEO fraud. Financial loss of [amount]. Evidence prepared."},
        ],
        "pakistan_specific": [
            "Bank fraud reporting: HBL: 111-111-425, MCB: 111-000-622, UBL: 111-825-888",
            "FIA Financial Crimes: report.fia.gov.pk | 0800-02345",
            "PECA 2016 Section 10: Electronic fraud is a criminal offense with imprisonment up to 7 years",
            "SBP Payment Systems Department can assist with inter-bank fraud cases",
        ],
        "tools_needed": ["Bank emergency contact numbers", "Email header analyzer", "FIA complaint form"],
    },
    {
        "name": "Lost/Stolen Device Response",
        "incident_type": "lost_device",
        "description": "Response when a company laptop, phone, or device is lost or stolen",
        "phases": [
            {"phase_name": "Immediate Containment", "time_target": "Within 1 hour", "steps": [
                {"step_number": 1, "action": "Remotely wipe the device immediately if MDM is in place", "owner": "IT Person", "time_estimate": "5 minutes", "critical": True, "details": "Use Microsoft Intune, Jamf, or Google MDM to remote wipe. Act before the thief can access data."},
                {"step_number": 2, "action": "Revoke all credentials on the device", "owner": "IT Person", "time_estimate": "15 minutes", "critical": True, "details": "Sign out all sessions for the device owner: email, VPN, cloud services, banking apps."},
                {"step_number": 3, "action": "Change all passwords that were stored on or accessible from the device", "owner": "IT Person + Device Owner", "time_estimate": "30 minutes", "critical": True, "details": "Browsers store passwords. If device wasn't encrypted, all saved passwords are compromised."},
                {"step_number": 4, "action": "Track device location if Find My Device is enabled", "owner": "IT Person + User", "time_estimate": "5 minutes", "critical": False, "details": "Windows: Find My Device in Settings. iPhone: iCloud.com. Android: findmydevice.google.com"},
            ]},
            {"phase_name": "Investigation", "time_target": "Within 4 hours", "steps": [
                {"step_number": 1, "action": "Determine what data was on the device", "owner": "IT Person + User", "time_estimate": "30 minutes", "critical": True, "details": "Customer data? Financial records? Credentials? This determines breach notification requirements."},
                {"step_number": 2, "action": "Was the device encrypted? Was it password protected?", "owner": "IT Person", "time_estimate": "15 minutes", "critical": True, "details": "BitLocker encryption means data is unreadable. No encryption = full data exposure."},
            ]},
            {"phase_name": "Eradication", "time_target": "Within 24 hours", "steps": [
                {"step_number": 1, "action": "File police report for stolen device", "owner": "Device Owner", "time_estimate": "2 hours", "critical": False, "details": "Needed for insurance claim. Get a copy of the FIR."},
            ]},
            {"phase_name": "Recovery", "time_target": "Within 48 hours", "steps": [
                {"step_number": 1, "action": "Provision replacement device with full encryption enabled from the start", "owner": "IT Person", "time_estimate": "4 hours", "critical": True, "details": "Enable BitLocker (Windows) or FileVault (Mac) on the new device before giving to user."},
            ]},
            {"phase_name": "Lessons Learned", "time_target": "Within 1 week", "steps": [
                {"step_number": 1, "action": "Implement full-disk encryption on all company devices", "owner": "IT Person", "time_estimate": "1 day", "critical": True, "details": "Windows BitLocker, Mac FileVault, Android/iPhone are encrypted by default with PIN. Enable it everywhere."},
                {"step_number": 2, "action": "Implement MDM solution for remote wipe capability", "owner": "IT Person", "time_estimate": "1-2 days", "critical": True, "details": "Microsoft Intune, Jamf for Mac, or Google Workspace MDM. Remote wipe is essential for mobile workforce."},
            ]},
        ],
        "notify_list": [
            {"who": "Management", "why": "Business decision on data breach implications", "when": "Immediately", "template_hint": "Company device belonging to [name] has been lost/stolen. We have remotely wiped it and are assessing data exposure."},
        ],
        "pakistan_specific": [
            "File FIR at nearest police station for stolen device",
            "If device contained customer data: PECA 2016 Section 14 breach notification may apply",
            "FIA Cybercrime if data is misused by thief: report.fia.gov.pk | 0800-02345",
            "Report IMEI to Pakistan Telecommunication Authority (PTA) for device blacklisting: www.pta.gov.pk",
        ],
        "tools_needed": ["MDM software (Microsoft Intune, Jamf)", "Remote wipe access", "Device IMEI number", "Insurance policy details"],
    },
    {
        "name": "Vendor/Third-Party Breach Response",
        "incident_type": "vendor_breach",
        "description": "Response when a vendor, supplier, or third-party service you use is breached",
        "phases": [
            {"phase_name": "Immediate Containment", "time_target": "Within 2 hours", "steps": [
                {"step_number": 1, "action": "Change all credentials shared with or managed by the vendor", "owner": "IT Person", "time_estimate": "1 hour", "critical": True, "details": "Any passwords the vendor had access to must be assumed compromised. Change them immediately."},
                {"step_number": 2, "action": "Revoke/rotate all API keys provided to the vendor", "owner": "IT Person", "time_estimate": "30 minutes", "critical": True, "details": "API keys are often target of supply chain attacks. Rotate all keys associated with the breached vendor."},
                {"step_number": 3, "action": "Suspend vendor's access to your systems if they have direct access", "owner": "IT Person", "time_estimate": "15 minutes", "critical": True, "details": "Temporarily revoke VPN, API, or direct system access until vendor confirms their systems are clean."},
            ]},
            {"phase_name": "Investigation", "time_target": "Within 24 hours", "steps": [
                {"step_number": 1, "action": "Contact vendor and get details of the breach — what data was exposed?", "owner": "Management", "time_estimate": "Varies", "critical": True, "details": "Ask specifically: Was our data exposed? What type? How many records? When? How was it discovered?"},
                {"step_number": 2, "action": "Review what data you shared with this vendor", "owner": "IT + Management", "time_estimate": "1 hour", "critical": True, "details": "Check contracts, data sharing agreements. What customer/business data did they have?"},
                {"step_number": 3, "action": "Review your own logs for suspicious activity from vendor systems", "owner": "IT Person", "time_estimate": "1 hour", "critical": True, "details": "If vendor had network access, check your firewall logs for anomalous traffic from their IP ranges."},
            ]},
            {"phase_name": "Eradication", "time_target": "Within 48 hours", "steps": [
                {"step_number": 1, "action": "Assess whether to continue using this vendor — evaluate alternatives", "owner": "Management", "time_estimate": "Varies", "critical": False, "details": "Consider the vendor's breach response quality, their security posture, and whether alternatives exist."},
            ]},
            {"phase_name": "Recovery", "time_target": "Within 1 week", "steps": [
                {"step_number": 1, "action": "Notify customers if their data was at the vendor and may be exposed", "owner": "Management + Legal", "time_estimate": "Varies", "critical": True, "details": "You may have legal obligation to notify customers even though the breach was at a vendor."},
            ]},
            {"phase_name": "Lessons Learned", "time_target": "Within 2 weeks", "steps": [
                {"step_number": 1, "action": "Conduct vendor security assessment for all critical suppliers", "owner": "Management + IT", "time_estimate": "1 week", "critical": True, "details": "Ask vendors for their security certifications, penetration test results, SOC 2 reports."},
                {"step_number": 2, "action": "Implement least-privilege access for all vendors", "owner": "IT Person", "time_estimate": "1-2 days", "critical": True, "details": "Vendors should only have access to systems and data they absolutely need. Review and restrict vendor access."},
            ]},
        ],
        "notify_list": [
            {"who": "Vendor Security Team", "why": "Get details and coordinate response", "when": "Immediately", "template_hint": "We are contacting you regarding your reported breach. We need to understand the scope of impact on our data."},
            {"who": "Management/Legal", "why": "Vendor liability, customer notification, contract implications", "when": "Within 2 hours", "template_hint": "Our vendor [name] has experienced a breach. Need to assess our data exposure and legal obligations."},
        ],
        "pakistan_specific": [
            "Review vendor contracts for breach notification obligations and SLAs",
            "If customer data was involved: PECA 2016 Section 14 may require you to notify customers",
            "Consider SBP vendor risk management guidelines for financial sector vendors",
        ],
        "tools_needed": ["Vendor contact list", "Data sharing agreements", "API key management system", "Vendor access audit logs"],
    },
    {
        "name": "Malware Infection Response",
        "incident_type": "malware",
        "description": "Response to malware, trojan, spyware, or general malicious software infection",
        "phases": [
            {"phase_name": "Immediate Containment", "time_target": "Within 30 minutes", "steps": [
                {"step_number": 1, "action": "Immediately disconnect infected machine from the network", "owner": "IT Person", "time_estimate": "2 minutes", "critical": True, "details": "Unplug ethernet cable AND disable WiFi. Malware can spread rapidly across network shares."},
                {"step_number": 2, "action": "Do NOT restart or shut down the machine yet", "owner": "IT Person", "time_estimate": "N/A", "critical": True, "details": "Some malware hides evidence in RAM. Keep powered on if possible to preserve forensic evidence."},
                {"step_number": 3, "action": "Identify what type of malware this appears to be", "owner": "IT Person", "time_estimate": "15 minutes", "critical": True, "details": "Look for symptoms: files being encrypted (ransomware), popup ads (adware), CPU spikes (cryptominer), unknown outbound connections (trojan/RAT)."},
                {"step_number": 4, "action": "Check other machines for similar symptoms", "owner": "IT Person", "time_estimate": "15 minutes", "critical": True, "details": "Malware often spreads to network shares and other machines. Quick scan of other systems."},
            ]},
            {"phase_name": "Investigation", "time_target": "Within 4 hours", "steps": [
                {"step_number": 1, "action": "Run malware sample through VirusTotal to identify the malware family", "owner": "IT Person", "time_estimate": "15 minutes", "critical": True, "details": "If you can safely copy the malware binary, upload to virustotal.com. Identifies the family and provides removal instructions."},
                {"step_number": 2, "action": "Review network logs for Command & Control (C2) communication", "owner": "IT Person", "time_estimate": "1 hour", "critical": True, "details": "Malware often communicates with attacker servers. Check firewall logs for unusual outbound connections."},
                {"step_number": 3, "action": "Identify the infection source — how did malware get in?", "owner": "IT Person", "time_estimate": "30 minutes", "critical": True, "details": "Email attachment? Malicious download? USB drive? Visiting a compromised website? Knowing the vector prevents reinfection."},
            ]},
            {"phase_name": "Eradication", "time_target": "Within 24 hours", "steps": [
                {"step_number": 1, "action": "Use dedicated malware removal tool for identified malware family", "owner": "IT Person", "time_estimate": "2 hours", "critical": True, "details": "Many AV vendors provide free dedicated removal tools. MalwareBytes is excellent for general malware removal."},
                {"step_number": 2, "action": "If removal fails or malware is persistent — reformat the machine", "owner": "IT Person", "time_estimate": "4 hours", "critical": True, "details": "Some malware (especially rootkits) cannot be fully removed without reinstalling the OS. Wipe and rebuild."},
                {"step_number": 3, "action": "Block C2 domains/IPs at the firewall", "owner": "IT Person", "time_estimate": "15 minutes", "critical": True, "details": "Even after removal, block known C2 addresses to prevent any remaining infections from communicating."},
            ]},
            {"phase_name": "Recovery", "time_target": "Within 48 hours", "steps": [
                {"step_number": 1, "action": "Restore data from pre-infection backup if files were damaged", "owner": "IT Person", "time_estimate": "Varies", "critical": False, "details": "Verify backup integrity. Scan restored files with AV before using them."},
                {"step_number": 2, "action": "Apply all pending software updates — patch the vulnerability used", "owner": "IT Person", "time_estimate": "2 hours", "critical": True, "details": "Most malware exploits known, patched vulnerabilities. Apply all updates."},
            ]},
            {"phase_name": "Lessons Learned", "time_target": "Within 1 week", "steps": [
                {"step_number": 1, "action": "Deploy endpoint protection across all devices", "owner": "IT Person", "time_estimate": "1 day", "critical": True, "details": "If you don't have AV/EDR on all devices, deploy now. Microsoft Defender is free and effective."},
                {"step_number": 2, "action": "Implement application whitelisting to prevent unauthorized software", "owner": "IT Person", "time_estimate": "1-2 days", "critical": False, "details": "Only allow approved software to run. Blocks most malware execution."},
            ]},
        ],
        "notify_list": [
            {"who": "Management", "why": "Business impact and decision-making on response", "when": "Immediately", "template_hint": "We have detected malware on [X] systems. Machines are isolated. Investigating scope and working on removal."},
        ],
        "pakistan_specific": [
            "Report to FIA Cybercrime if malware appears targeted/state-sponsored: report.fia.gov.pk",
            "Share malware sample with CERT (Computer Emergency Response Team) if one is available in your sector",
            "PECA 2016 Section 9: Spreading malicious code is a criminal offense — report the incident",
        ],
        "tools_needed": ["MalwareBytes (free tier)", "VirusTotal.com", "Microsoft Defender", "Clean OS installation media", "Offline backup"],
    },
]


def get_builtin_playbooks() -> list[dict]:
    return BUILTIN_PLAYBOOKS
