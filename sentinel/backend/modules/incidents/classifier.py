import json

import anthropic

from config import settings


async def classify_incident(description: str, affected_systems: str) -> dict:
    if not settings.ANTHROPIC_API_KEY:
        return {
            "incident_type": "other",
            "severity": "medium",
            "severity_reason": "AI classification unavailable — no API key configured.",
            "affected_data_types": [],
            "iocs_extracted": [],
            "peca_reporting_required": False,
            "peca_reason": "Unable to determine without AI analysis.",
            "initial_containment": ["Isolate affected systems", "Change passwords", "Contact IT support"],
        }

    client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)

    prompt = f"""You are a cybersecurity incident response expert. Analyze this incident and return JSON.

Incident Description: {description}
Affected Systems: {affected_systems}

Return ONLY valid JSON:
{{
  "incident_type": "ransomware|phishing|account_takeover|data_breach|insider|ddos|social_eng|lost_device|vendor_breach|malware|other",
  "severity": "critical|high|medium|low",
  "severity_reason": "one sentence explaining severity",
  "affected_data_types": ["PII","financial","credentials","IP","health"],
  "iocs_extracted": ["any IPs, domains, hashes, emails mentioned"],
  "peca_reporting_required": true or false,
  "peca_reason": "why PECA 2016 reporting is or is not required",
  "initial_containment": ["top 3 immediate actions to take right now"]
}}"""

    try:
        message = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        text = message.content[0].text.strip()
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        return json.loads(text)
    except Exception as e:
        return {
            "incident_type": "other",
            "severity": "medium",
            "severity_reason": f"AI classification failed: {str(e)}",
            "affected_data_types": [],
            "iocs_extracted": [],
            "peca_reporting_required": False,
            "peca_reason": "Unable to determine.",
            "initial_containment": ["Isolate affected systems", "Document what happened", "Contact IT support"],
        }
