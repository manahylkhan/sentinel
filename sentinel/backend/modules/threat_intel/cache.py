import json
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from models import TICache


def get_cached_result(db: Session, indicator: str) -> dict | None:
    now = datetime.utcnow()
    cached = (
        db.query(TICache)
        .filter(TICache.indicator == indicator, TICache.expires_at > now)
        .first()
    )
    if not cached:
        return None
    return {
        "id": cached.id,
        "indicator": cached.indicator,
        "indicator_type": cached.indicator_type,
        "feed_results": json.loads(cached.results_json),
        "verdict": cached.verdict,
        "ai_summary": cached.ai_summary,
        "ai_action": cached.ai_action,
        "confidence": cached.confidence,
        "flagged_by": json.loads(cached.flagged_by) if cached.flagged_by else [],
        "cached": True,
        "created_at": cached.created_at.isoformat(),
    }


def save_to_cache(
    db: Session,
    indicator: str,
    indicator_type: str,
    feed_results: list,
    verdict: str,
    ai_summary: str,
    ai_action: str,
    confidence: str,
    flagged_by: list,
) -> TICache:
    entry = TICache(
        indicator=indicator,
        indicator_type=indicator_type,
        results_json=json.dumps(feed_results),
        verdict=verdict,
        ai_summary=ai_summary,
        ai_action=ai_action,
        confidence=confidence,
        flagged_by=json.dumps(flagged_by),
        expires_at=datetime.utcnow() + timedelta(hours=24),
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry
