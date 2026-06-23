import json

import anthropic

from config import settings


async def ai_analyze_logs(
    entries: list[dict],
    rule_findings: list[dict],
    log_type: str,
    ti_flags: list[dict],
) -> dict:
    if not settings.ANTHROPIC_API_KEY:
        return {
            "summary": f"Log analysis complete. Found {len(rule_findings)} rule-based finding(s) across {len(entries)} log entries. Configure Anthropic API key for AI-powered plain-English analysis.",
            "top_concerns": [f["description"] for f in rule_findings[:3]],
            "normal_explanation": "No AI analysis available.",
            "recommended_actions": ["Review rule-based findings above", "Block flagged IPs at firewall", "Investigate off-hours logins"],
        }

    # Stats
    unique_ips = len({e.get("source_ip") for e in entries if e.get("source_ip")})
    error_count = sum(1 for e in entries if e.get("is_error"))
    error_rate = f"{error_count / max(len(entries), 1) * 100:.1f}%"

    stats = {
        "total_entries": len(entries),
        "unique_ips": unique_ips,
        "log_type": log_type,
        "error_rate": error_rate,
        "rule_findings_count": len(rule_findings),
    }

    prompt = f"""You are a SOC analyst. Analyze these log statistics and findings for a small business owner.

Stats: {json.dumps(stats)}

Rule-Based Findings: {json.dumps(rule_findings[:10])}

TI-Flagged IPs: {json.dumps(ti_flags[:5])}

Sample Log Entries (most suspicious): {json.dumps(entries[:20])}

Write a plain-English analysis that a NON-TECHNICAL business owner can understand.
Return ONLY valid JSON:
{{
  "summary": "2-3 sentence overview of what the logs show",
  "top_concerns": ["specific concern 1", "specific concern 2", "specific concern 3"],
  "normal_explanation": "what looks normal in these logs",
  "recommended_actions": ["specific action 1", "specific action 2", "specific action 3"]
}}"""

    client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)
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
            "summary": f"AI analysis encountered an error: {str(e)}. Review rule-based findings below.",
            "top_concerns": [f["description"] for f in rule_findings[:3]],
            "normal_explanation": "Unable to determine.",
            "recommended_actions": ["Review findings manually"],
        }
