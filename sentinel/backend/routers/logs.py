import re
import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from config import settings
from database import get_db
from modules.logs.ai_analyst import ai_analyze_logs
from modules.logs.detector import detect_log_type
from modules.logs.parsers.apache import parse_apache
from modules.logs.parsers.generic import parse_generic
from modules.logs.parsers.linux_auth import parse_linux_auth
from modules.logs.rules import apply_detection_rules
from modules.threat_intel.ai_verdict import generate_verdict
from modules.threat_intel.cache import get_cached_result, save_to_cache
from modules.threat_intel.feeds import check_all_feeds

router = APIRouter(prefix="/api/logs", tags=["logs"])

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB


@router.post("/analyze")
async def analyze_log(file: UploadFile = File(...), db: Session = Depends(get_db)):
    content_bytes = await file.read()

    if len(content_bytes) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="File too large. Maximum 50MB.")

    # Decode with fallback
    try:
        content = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        try:
            content = content_bytes.decode("latin-1")
        except Exception:
            content = content_bytes.decode("utf-8", errors="replace")

    # Detect and parse
    log_type = detect_log_type(content)
    parser_map = {
        "linux_auth": parse_linux_auth,
        "apache": parse_apache,
        "nginx": parse_apache,
        "windows_security": parse_generic,
        "syslog": parse_generic,
        "generic": parse_generic,
    }
    parse_fn = parser_map.get(log_type, parse_generic)
    entries = parse_fn(content)

    # Extract unique IPs
    all_ips_in_content = list(set(_IP_RE.findall(content)))

    # TI check on unique IPs (cap at 20 to avoid rate limits)
    ti_flags = []
    for ip in all_ips_in_content[:20]:
        cached = get_cached_result(db, ip)
        if cached and cached.get("verdict") in ("malicious", "suspicious"):
            ti_flags.append({"ip": ip, "verdict": cached["verdict"], "summary": cached.get("ai_summary", "")})
        elif not cached:
            try:
                feed_data = await check_all_feeds(ip, "ip", settings)
                if feed_data.get("flagged_by"):
                    ai_result = await generate_verdict(ip, feed_data)
                    save_to_cache(
                        db=db,
                        indicator=ip,
                        indicator_type="ip",
                        feed_results=feed_data["feed_results"],
                        verdict=ai_result["verdict"],
                        ai_summary=ai_result["summary"],
                        ai_action=ai_result["recommended_action"],
                        confidence=ai_result["confidence"],
                        flagged_by=feed_data["flagged_by"],
                    )
                    if ai_result["verdict"] in ("malicious", "suspicious"):
                        ti_flags.append({"ip": ip, "verdict": ai_result["verdict"], "summary": ai_result["summary"]})
            except Exception:
                pass

    # Detection rules
    rule_findings = apply_detection_rules(entries, log_type)

    # AI analysis
    ai_analysis = await ai_analyze_logs(entries, rule_findings, log_type, ti_flags)

    # Stats
    unique_ips = list({e.get("source_ip") for e in entries if e.get("source_ip")})
    error_count = sum(1 for e in entries if e.get("is_error"))

    timestamps = [e.get("timestamp") for e in entries if e.get("timestamp")]
    time_range = None
    if timestamps:
        time_range = f"{min(timestamps)} — {max(timestamps)}"

    return {
        "file_name": file.filename,
        "log_type": log_type,
        "total_entries": len(entries),
        "unique_ips": unique_ips,
        "unique_ip_count": len(unique_ips),
        "error_count": error_count,
        "error_rate": f"{error_count / max(len(entries), 1) * 100:.1f}%",
        "time_range": time_range,
        "rule_findings": rule_findings,
        "ti_flagged_ips": ti_flags,
        "ai_analysis": ai_analysis,
    }
