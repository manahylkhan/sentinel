import re
from datetime import datetime


_LINE_RE = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+"
    r"(?P<host>\S+)\s+(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.+)"
)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_USER_RE = re.compile(r"(?:for|user)\s+(\S+)")


def parse_linux_auth(content: str) -> list[dict]:
    entries = []
    current_year = datetime.utcnow().year

    for line in content.splitlines():
        m = _LINE_RE.match(line.strip())
        if not m:
            continue

        msg = m.group("message")
        event_type = "other"
        if "Accepted" in msg and ("password" in msg or "publickey" in msg):
            event_type = "login_success"
        elif "Failed" in msg or "Invalid" in msg or "authentication failure" in msg:
            event_type = "login_fail"
        elif "sudo" in m.group("process").lower():
            event_type = "sudo"
        elif "new user" in msg.lower() or "useradd" in msg.lower():
            event_type = "new_user"

        ip_match = _IP_RE.search(msg)
        user_match = _USER_RE.search(msg)

        try:
            ts = datetime.strptime(
                f"{m.group('month')} {m.group('day')} {current_year} {m.group('time')}",
                "%b %d %Y %H:%M:%S",
            )
        except ValueError:
            ts = None

        entries.append({
            "timestamp": ts.isoformat() if ts else None,
            "host": m.group("host"),
            "process": m.group("process"),
            "pid": m.group("pid"),
            "message": msg,
            "event_type": event_type,
            "username": user_match.group(1) if user_match else None,
            "source_ip": ip_match.group(0) if ip_match else None,
        })

    return entries
