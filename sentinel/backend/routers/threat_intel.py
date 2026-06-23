import json
import re
from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from config import settings
from database import get_db
from models import IOC, TICache
from modules.threat_intel.ai_verdict import generate_verdict
from modules.threat_intel.cache import get_cached_result, save_to_cache
from modules.threat_intel.feeds import check_all_feeds

router = APIRouter(prefix="/api/ti", tags=["threat_intel"])


# ── Type auto-detection ───────────────────────────────────────────────────────

def detect_indicator_type(indicator: str) -> str:
    indicator = indicator.strip()
    # SHA256
    if re.match(r"^[a-fA-F0-9]{64}$", indicator):
        return "hash"
    # SHA1
    if re.match(r"^[a-fA-F0-9]{40}$", indicator):
        return "hash"
    # MD5
    if re.match(r"^[a-fA-F0-9]{32}$", indicator):
        return "hash"
    # URL
    if indicator.startswith("http://") or indicator.startswith("https://"):
        return "url"
    # Email
    if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", indicator):
        return "email"
    # IP
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", indicator):
        return "ip"
    # Domain (fallback)
    return "domain"


# ── Request/Response models ───────────────────────────────────────────────────

class CheckRequest(BaseModel):
    indicator: str
    indicator_type: str | None = None


class BulkCheckRequest(BaseModel):
    indicators: list[dict]


# ── Helpers ───────────────────────────────────────────────────────────────────

def auto_add_malicious_ioc(db: Session, indicator: str, ind_type: str, verdict: str, summary: str):
    if verdict not in ("malicious", "suspicious"):
        return
    existing = db.query(IOC).filter(IOC.indicator == indicator).first()
    if existing:
        return
    severity = "high" if verdict == "malicious" else "medium"
    ioc = IOC(
        indicator=indicator,
        indicator_type=ind_type,
        verdict=verdict,
        severity=severity,
        source="ti_check",
        status="active",
        notes=summary,
    )
    db.add(ioc)
    db.commit()


def build_response(cache_entry, feed_data: dict, ai_result: dict, indicator: str, ind_type: str) -> dict:
    return {
        "id": cache_entry.id if cache_entry else None,
        "indicator": indicator,
        "indicator_type": ind_type,
        "verdict": ai_result["verdict"],
        "confidence": ai_result["confidence"],
        "ai_summary": ai_result["summary"],
        "ai_action": ai_result["recommended_action"],
        "feed_results": feed_data.get("feed_results", []),
        "flagged_by": feed_data.get("flagged_by", []),
        "total_feeds_checked": feed_data.get("total_feeds_checked", 0),
        "cached": False,
        "checked_at": datetime.utcnow().isoformat(),
    }


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/check")
async def check_indicator(req: CheckRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    indicator = req.indicator.strip()
    ind_type = req.indicator_type or detect_indicator_type(indicator)

    # Cache hit
    cached = get_cached_result(db, indicator)
    if cached:
        return cached

    # Parallel feed queries
    feed_data = await check_all_feeds(indicator, ind_type, settings)

    # AI verdict
    ai_result = await generate_verdict(indicator, feed_data)

    # Save to cache
    cache_entry = save_to_cache(
        db=db,
        indicator=indicator,
        indicator_type=ind_type,
        feed_results=feed_data["feed_results"],
        verdict=ai_result["verdict"],
        ai_summary=ai_result["summary"],
        ai_action=ai_result["recommended_action"],
        confidence=ai_result["confidence"],
        flagged_by=feed_data["flagged_by"],
    )

    # Auto-add to IOC tracker in background
    background_tasks.add_task(
        auto_add_malicious_ioc,
        db, indicator, ind_type, ai_result["verdict"], ai_result["summary"]
    )

    return build_response(cache_entry, feed_data, ai_result, indicator, ind_type)


@router.post("/bulk-check")
async def bulk_check(req: BulkCheckRequest, db: Session = Depends(get_db)):
    if len(req.indicators) > 50:
        raise HTTPException(status_code=400, detail="Maximum 50 indicators per request")

    results = []
    for item in req.indicators:
        indicator = item.get("value", "").strip()
        ind_type = item.get("type") or detect_indicator_type(indicator)
        if not indicator:
            continue

        cached = get_cached_result(db, indicator)
        if cached:
            results.append(cached)
            continue

        feed_data = await check_all_feeds(indicator, ind_type, settings)
        ai_result = await generate_verdict(indicator, feed_data)
        cache_entry = save_to_cache(
            db=db,
            indicator=indicator,
            indicator_type=ind_type,
            feed_results=feed_data["feed_results"],
            verdict=ai_result["verdict"],
            ai_summary=ai_result["summary"],
            ai_action=ai_result["recommended_action"],
            confidence=ai_result["confidence"],
            flagged_by=feed_data["flagged_by"],
        )
        results.append(build_response(cache_entry, feed_data, ai_result, indicator, ind_type))

    return {"results": results, "total": len(results)}


@router.get("/history")
def get_history(db: Session = Depends(get_db)):
    entries = (
        db.query(TICache)
        .order_by(TICache.created_at.desc())
        .limit(50)
        .all()
    )
    return [
        {
            "id": e.id,
            "indicator": e.indicator,
            "indicator_type": e.indicator_type,
            "verdict": e.verdict,
            "confidence": e.confidence,
            "ai_summary": e.ai_summary,
            "flagged_by": json.loads(e.flagged_by) if e.flagged_by else [],
            "created_at": e.created_at.isoformat(),
        }
        for e in entries
    ]


@router.get("/detect-type")
def detect_type(indicator: str):
    return {"indicator": indicator, "type": detect_indicator_type(indicator)}
