import re
from datetime import datetime


_LINE_RE = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<datetime>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<url>\S+)\s+\S+"\s+(?P<status>\d+)\s+(?P<bytes>\S+)'
)

_SUSPICIOUS_PATTERNS = [
    "../", "etc/passwd", ".php?cmd=", "eval(", "/wp-admin",
    "/phpmyadmin", "/admin", "base64_decode", "union select",
    "<script", "../../", "/etc/shadow", "cmd.exe",
]


def _is_suspicious(url: str) -> bool:
    url_lower = url.lower()
    return any(p in url_lower for p in _SUSPICIOUS_PATTERNS)


def parse_apache(content: str) -> list[dict]:
    entries = []

    for line in content.splitlines():
        m = _LINE_RE.match(line.strip())
        if not m:
            continue

        status = int(m.group("status"))
        url = m.group("url")
        try:
            ts = datetime.strptime(m.group("datetime").split()[0], "%d/%b/%Y:%H:%M:%S")
        except ValueError:
            ts = None

        entries.append({
            "timestamp": ts.isoformat() if ts else None,
            "source_ip": m.group("ip"),
            "method": m.group("method"),
            "url": url,
            "status_code": status,
            "bytes": m.group("bytes"),
            "is_error": status >= 400,
            "is_suspicious_url": _is_suspicious(url),
            "event_type": "http_request",
        })

    return entries
