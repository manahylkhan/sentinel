import re


def detect_log_type(content: str) -> str:
    sample = content[:1000]

    if re.search(r"EventID|Security.*Microsoft|Windows.*Event", sample, re.IGNORECASE):
        return "windows_security"
    if re.search(r"sshd\[|sudo\[|pam_unix\(|Accepted password|Failed password", sample):
        return "linux_auth"
    if re.search(r'\d+\.\d+\.\d+\.\d+.*\[.*\].*"(?:GET|POST|PUT|DELETE|HEAD)', sample):
        if "nginx" in sample.lower():
            return "nginx"
        return "apache"
    if re.search(r"<\d+>.*\w+\[\d+\]", sample):
        return "syslog"

    return "generic"
