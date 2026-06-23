from collections import defaultdict
from datetime import datetime, timedelta


def apply_detection_rules(entries: list[dict], log_type: str) -> list[dict]:
    findings = []

    findings += _rule_brute_force(entries)
    findings += _rule_off_hours(entries)
    findings += _rule_new_admin(entries)
    findings += _rule_suspicious_url(entries)
    findings += _rule_multiple_sources(entries)

    return findings


def _parse_ts(ts_str: str | None) -> datetime | None:
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str)
    except Exception:
        return None


def _rule_brute_force(entries: list[dict]) -> list[dict]:
    findings = []
    # Group failed logins by source IP in 5-minute windows
    fails = defaultdict(list)
    for e in entries:
        if e.get("event_type") == "login_fail" and e.get("source_ip"):
            ts = _parse_ts(e.get("timestamp"))
            fails[e["source_ip"]].append(ts)

    for ip, timestamps in fails.items():
        valid_ts = [t for t in timestamps if t]
        valid_ts.sort()
        window_count = 0
        for i, ts in enumerate(valid_ts):
            count = sum(1 for t in valid_ts[i:] if t - ts <= timedelta(minutes=5))
            window_count = max(window_count, count)

        total = len(timestamps)
        if total >= 10:
            severity = "high" if total >= 50 else "medium"
            findings.append({
                "rule": "Brute Force Attempt",
                "severity": severity,
                "description": f"IP {ip} made {total} failed login attempts",
                "count": total,
                "affected_ips": [ip],
                "recommendation": f"Block IP {ip} at the firewall immediately.",
            })

    return findings


def _rule_off_hours(entries: list[dict]) -> list[dict]:
    findings = []
    business_hours = set(range(6, 19))
    off_hours_logins = []

    for e in entries:
        if e.get("event_type") == "login_success":
            ts = _parse_ts(e.get("timestamp"))
            if ts and ts.hour not in business_hours:
                off_hours_logins.append({
                    "user": e.get("username", "unknown"),
                    "ip": e.get("source_ip"),
                    "time": ts.isoformat(),
                })

    if off_hours_logins:
        findings.append({
            "rule": "Off-Hours Login",
            "severity": "medium",
            "description": f"{len(off_hours_logins)} successful login(s) outside business hours (6am-7pm)",
            "count": len(off_hours_logins),
            "affected_ips": list({l["ip"] for l in off_hours_logins if l["ip"]}),
            "recommendation": "Review these logins — confirm with the users that they were authorized.",
            "details": off_hours_logins[:5],
        })

    return findings


def _rule_new_admin(entries: list[dict]) -> list[dict]:
    findings = []
    for e in entries:
        msg = e.get("message", "").lower()
        if e.get("event_type") == "new_user" or "new user" in msg or "useradd" in msg or "usermod" in msg and "sudo" in msg:
            findings.append({
                "rule": "New User / Privilege Escalation",
                "severity": "high",
                "description": f"New user created or privilege changes detected: {e.get('message', '')[:100]}",
                "count": 1,
                "affected_ips": [e.get("source_ip")] if e.get("source_ip") else [],
                "recommendation": "Verify this was an authorized action. Check with IT/HR.",
            })

    return findings


def _rule_suspicious_url(entries: list[dict]) -> list[dict]:
    suspicious = [e for e in entries if e.get("is_suspicious_url")]
    if not suspicious:
        return []
    unique_ips = list({e["source_ip"] for e in suspicious if e.get("source_ip")})
    count = len(suspicious)
    return [{
        "rule": "Suspicious URL Pattern",
        "severity": "high" if count > 10 else "medium",
        "description": f"{count} request(s) with suspicious URL patterns (path traversal, admin access, injection attempts)",
        "count": count,
        "affected_ips": unique_ips,
        "recommendation": "Review these requests — may indicate active attack or reconnaissance.",
        "sample_urls": [e.get("url", "") for e in suspicious[:3]],
    }]


def _rule_multiple_sources(entries: list[dict]) -> list[dict]:
    findings = []
    user_ips = defaultdict(set)

    for e in entries:
        user = e.get("username")
        ip = e.get("source_ip")
        if user and ip and e.get("event_type") == "login_success":
            user_ips[user].add(ip)

    for user, ips in user_ips.items():
        if len(ips) > 3:
            findings.append({
                "rule": "Account Accessed from Multiple Locations",
                "severity": "high",
                "description": f"User '{user}' logged in from {len(ips)} different IP addresses",
                "count": len(ips),
                "affected_ips": list(ips),
                "recommendation": f"Contact {user} to verify all logins were authorized. May indicate credential compromise.",
            })

    return findings
