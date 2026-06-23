import json

import anthropic

from config import settings


async def generate_verdict(indicator: str, feed_data: dict) -> dict:
    if not settings.ANTHROPIC_API_KEY:
        flagged_count = len(feed_data.get("flagged_by", []))
        verdict = "malicious" if flagged_count >= 2 else "suspicious" if flagged_count == 1 else "clean"
        return {
            "verdict": verdict,
            "confidence": "low",
            "summary": f"No AI analysis available (API key not configured). {flagged_count} feed(s) flagged this indicator.",
            "recommended_action": "Configure Anthropic API key for detailed AI analysis.",
        }

    client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)

    feed_summary = json.dumps(feed_data.get("feed_results", []), indent=2)
    flagged_by = feed_data.get("flagged_by", [])
    total_feeds = feed_data.get("total_feeds_checked", 0)

    prompt = f"""You are a threat analyst. Based on these threat feed results for the indicator "{indicator}", provide a verdict.

Feed Results ({total_feeds} feeds checked, flagged by: {flagged_by}):
{feed_summary}

Return ONLY valid JSON with this exact structure:
{{
  "verdict": "malicious|suspicious|clean|unknown",
  "confidence": "high|medium|low",
  "summary": "2-3 sentence plain English explanation a non-technical business owner can understand",
  "recommended_action": "Specific actionable step to take right now"
}}"""

    try:
        message = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=512,
            messages=[{"role": "user", "content": prompt}],
        )
        text = message.content[0].text.strip()
        # Strip markdown code fences if present
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        result = json.loads(text)
        return {
            "verdict": result.get("verdict", "unknown"),
            "confidence": result.get("confidence", "low"),
            "summary": result.get("summary", ""),
            "recommended_action": result.get("recommended_action", ""),
        }
    except Exception as e:
        return {
            "verdict": "unknown",
            "confidence": "low",
            "summary": f"AI analysis failed: {str(e)}",
            "recommended_action": "Review feed results manually.",
        }
