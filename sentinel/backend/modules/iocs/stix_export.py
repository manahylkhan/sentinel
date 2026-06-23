import json
from datetime import datetime


def export_to_stix(iocs: list[dict]) -> str:
    """Generate a STIX 2.1 bundle from a list of IOC dicts without requiring the stix2 library."""
    objects = []
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    type_pattern_map = {
        "ip": lambda v: f"[ipv4-addr:value = '{v}']",
        "domain": lambda v: f"[domain-name:value = '{v}']",
        "url": lambda v: f"[url:value = '{v}']",
        "hash": lambda v: f"[file:hashes.'SHA-256' = '{v}']",
        "email": lambda v: f"[email-addr:value = '{v}']",
    }

    for ioc in iocs:
        ind_type = ioc.get("indicator_type", "ip")
        value = ioc.get("indicator", "")
        pattern_fn = type_pattern_map.get(ind_type, type_pattern_map["ip"])
        pattern = pattern_fn(value)

        indicator_obj = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{ioc['id']}",
            "created": now,
            "modified": now,
            "name": f"{ind_type.upper()} - {value}",
            "description": ioc.get("notes", ""),
            "indicator_types": [_map_verdict_to_stix(ioc.get("verdict", "unknown"))],
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": now,
            "labels": [ioc.get("verdict", "unknown"), ind_type],
            "confidence": _map_severity_to_confidence(ioc.get("severity", "medium")),
        }
        objects.append(indicator_obj)

    bundle = {
        "type": "bundle",
        "id": f"bundle--sentinel-export-{now.replace(':', '-')}",
        "spec_version": "2.1",
        "objects": objects,
    }
    return json.dumps(bundle, indent=2)


def _map_verdict_to_stix(verdict: str) -> str:
    mapping = {
        "malicious": "malicious-activity",
        "suspicious": "anomalous-activity",
        "clean": "benign",
        "unknown": "unknown",
    }
    return mapping.get(verdict, "unknown")


def _map_severity_to_confidence(severity: str) -> int:
    mapping = {"critical": 95, "high": 80, "medium": 60, "low": 40, "info": 20}
    return mapping.get(severity, 50)
