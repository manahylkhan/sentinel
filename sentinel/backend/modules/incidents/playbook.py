import json

import anthropic

from config import settings


async def generate_playbook(
    incident_type: str,
    severity: str,
    description: str,
    affected_systems: str,
) -> dict:
    if not settings.ANTHROPIC_API_KEY:
        return _fallback_playbook(incident_type)

    client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)

    prompt = f"""You are a senior IR consultant creating a response playbook for a small business with NO dedicated IT security staff.
Be specific, practical, and use plain language.

Incident Type: {incident_type}
Severity: {severity}
Description: {description}
Affected Systems: {affected_systems}
Organization Context: Small/medium business in Pakistan

Return ONLY valid JSON:
{{
  "phases": [
    {{
      "phase_name": "Immediate Containment",
      "time_target": "Within 1 hour",
      "steps": [
        {{
          "step_number": 1,
          "action": "Specific action to take",
          "owner": "IT Person|Management|All Staff|HR|Legal",
          "time_estimate": "5 minutes",
          "critical": true,
          "details": "Detailed explanation of how to do this step"
        }}
      ]
    }},
    {{
      "phase_name": "Investigation",
      "time_target": "Within 4 hours",
      "steps": []
    }},
    {{
      "phase_name": "Eradication",
      "time_target": "Within 24 hours",
      "steps": []
    }},
    {{
      "phase_name": "Recovery",
      "time_target": "Within 72 hours",
      "steps": []
    }},
    {{
      "phase_name": "Lessons Learned",
      "time_target": "Within 1 week",
      "steps": []
    }}
  ],
  "notify_list": [
    {{
      "who": "Management/CEO",
      "why": "Reason they need to know",
      "when": "Immediately",
      "template_hint": "Brief script for what to say"
    }}
  ],
  "pakistan_specific": [
    "FIA Cybercrime Wing: report.fia.gov.pk | 0800-02345",
    "PECA 2016 Section X: specific obligation if applicable"
  ],
  "tools_needed": ["List of tools or resources needed"]
}}"""

    try:
        message = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=3000,
            messages=[{"role": "user", "content": prompt}],
        )
        text = message.content[0].text.strip()
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        return json.loads(text)
    except Exception as e:
        return _fallback_playbook(incident_type, error=str(e))


def _fallback_playbook(incident_type: str, error: str = "") -> dict:
    return {
        "phases": [
            {
                "phase_name": "Immediate Containment",
                "time_target": "Within 1 hour",
                "steps": [
                    {"step_number": 1, "action": "Isolate affected systems from the network", "owner": "IT Person", "time_estimate": "10 minutes", "critical": True, "details": "Disconnect affected computers from LAN/WiFi to prevent spread."},
                    {"step_number": 2, "action": "Document what you see — take screenshots", "owner": "IT Person", "time_estimate": "5 minutes", "critical": True, "details": "Evidence is critical for later investigation and reporting."},
                    {"step_number": 3, "action": "Notify management immediately", "owner": "IT Person", "time_estimate": "5 minutes", "critical": True, "details": "Management needs to be aware and may need to make decisions."},
                ],
            },
            {"phase_name": "Investigation", "time_target": "Within 4 hours", "steps": [{"step_number": 1, "action": "Identify scope of the incident", "owner": "IT Person", "time_estimate": "1 hour", "critical": True, "details": "Determine how many systems are affected and what data may be at risk."}]},
            {"phase_name": "Eradication", "time_target": "Within 24 hours", "steps": [{"step_number": 1, "action": "Remove malicious content and patch vulnerabilities", "owner": "IT Person", "time_estimate": "Varies", "critical": True, "details": "Clean infected systems and address the root cause."}]},
            {"phase_name": "Recovery", "time_target": "Within 72 hours", "steps": [{"step_number": 1, "action": "Restore systems from clean backups", "owner": "IT Person", "time_estimate": "Varies", "critical": True, "details": "Restore from the most recent clean backup available."}]},
            {"phase_name": "Lessons Learned", "time_target": "Within 1 week", "steps": [{"step_number": 1, "action": "Conduct post-incident review meeting", "owner": "Management + IT", "time_estimate": "1 hour", "critical": False, "details": "Discuss what happened, what worked, and what needs to improve."}]},
        ],
        "notify_list": [{"who": "Management/CEO", "why": "Organizational awareness and decision-making authority", "when": "Immediately", "template_hint": "We have detected a security incident affecting [systems]. We are investigating and will provide updates."}],
        "pakistan_specific": ["FIA Cybercrime Wing: report.fia.gov.pk | 0800-02345", "Consider PECA 2016 reporting obligations — consult legal counsel."],
        "tools_needed": ["Antivirus software", "Backup solution", "System documentation"],
        "note": f"Playbook generated with defaults{' — AI error: ' + error if error else ''}",
    }
