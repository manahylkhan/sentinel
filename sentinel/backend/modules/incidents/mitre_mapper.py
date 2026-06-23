import json

import anthropic

from config import settings


async def map_to_mitre(incident_type: str, description: str) -> list[dict]:
    if not settings.ANTHROPIC_API_KEY:
        return []

    client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)

    prompt = f"""Map this cybersecurity incident to MITRE ATT&CK techniques.

Incident Type: {incident_type}
Description: {description}

Return ONLY valid JSON array (max 5 techniques, only high-confidence ones):
[
  {{
    "technique_id": "T1566",
    "technique_name": "Phishing",
    "tactic": "Initial Access",
    "confidence": "high|medium|low"
  }}
]"""

    try:
        client_obj = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)
        message = client_obj.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=512,
            messages=[{"role": "user", "content": prompt}],
        )
        text = message.content[0].text.strip()
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        result = json.loads(text)
        return result if isinstance(result, list) else []
    except Exception:
        return []
