import json
import re

import anthropic

from config import settings

_COMMON_DOMAINS = {
    "com", "org", "net", "gov", "edu", "io", "co", "pk", "gmail", "yahoo",
    "outlook", "hotmail", "google", "microsoft", "apple", "amazon",
}

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL_RE = re.compile(r"https?://[^\s\"'<>]+")
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}\b")


def _is_valid_ip(ip: str) -> bool:
    parts = ip.split(".")
    return all(0 <= int(p) <= 255 for p in parts)


def extract_iocs_regex(text: str) -> list[dict]:
    found = []
    seen = set()

    def add(value: str, ioc_type: str):
        key = f"{ioc_type}:{value.lower()}"
        if key not in seen:
            seen.add(key)
            found.append({"value": value, "type": ioc_type, "confidence": "regex"})

    # URLs first (before domain extraction removes them)
    for m in _URL_RE.findall(text):
        add(m, "url")

    # Emails
    for m in _EMAIL_RE.findall(text):
        add(m, "email")

    # Hashes (longest first to avoid collisions)
    for m in _SHA256_RE.findall(text):
        add(m, "hash")
    for m in _SHA1_RE.findall(text):
        add(m, "hash")
    for m in _MD5_RE.findall(text):
        add(m, "hash")

    # IPs
    for m in _IP_RE.findall(text):
        try:
            if _is_valid_ip(m):
                add(m, "ip")
        except Exception:
            pass

    # Domains (exclude already-seen URLs and common words)
    for m in _DOMAIN_RE.findall(text):
        parts = m.split(".")
        if parts[-1].lower() in _COMMON_DOMAINS and len(parts) >= 2:
            add(m.lower(), "domain")

    return found


async def extract_iocs_ai(text: str, regex_iocs: list[dict]) -> list[dict]:
    if not settings.ANTHROPIC_API_KEY:
        return []

    existing = [i["value"] for i in regex_iocs]
    client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)

    prompt = f"""Extract all Indicators of Compromise (IOCs) from this text that were NOT already found by regex.
Already found: {existing}

Text: {text}

Return ONLY valid JSON array (empty array if none):
[{{"value": "indicator_value", "type": "ip|domain|url|hash|email", "confidence": "ai"}}]"""

    try:
        message = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=512,
            messages=[{"role": "user", "content": prompt}],
        )
        response_text = message.content[0].text.strip()
        if response_text.startswith("```"):
            response_text = response_text.split("```")[1]
            if response_text.startswith("json"):
                response_text = response_text[4:]
        result = json.loads(response_text)
        return result if isinstance(result, list) else []
    except Exception:
        return []


async def extract_iocs_from_text(text: str) -> list[dict]:
    regex_iocs = extract_iocs_regex(text)
    ai_iocs = await extract_iocs_ai(text, regex_iocs)

    # Merge and deduplicate
    seen = {f"{i['type']}:{i['value'].lower()}" for i in regex_iocs}
    for ioc in ai_iocs:
        key = f"{ioc['type']}:{ioc['value'].lower()}"
        if key not in seen:
            seen.add(key)
            regex_iocs.append(ioc)

    return regex_iocs
