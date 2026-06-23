import re

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def parse_generic(content: str) -> list[dict]:
    entries = []
    for i, line in enumerate(content.splitlines()):
        stripped = line.strip()
        if not stripped:
            continue
        ips = _IP_RE.findall(stripped)
        entries.append({
            "line_number": i + 1,
            "message": stripped,
            "source_ip": ips[0] if ips else None,
            "all_ips": ips,
            "event_type": "generic",
            "timestamp": None,
        })
    return entries
