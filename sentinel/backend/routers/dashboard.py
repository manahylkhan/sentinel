from collections import defaultdict
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import get_db
from models import IOC, Incident, TICache

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


def calculate_risk_score(open_incidents: list) -> int:
    score = 0
    peca_open = 0
    for inc in open_incidents:
        if inc.severity == "critical":
            score += 40
        elif inc.severity == "high":
            score += 20
        elif inc.severity == "medium":
            score += 10
        elif inc.severity == "low":
            score += 5
        if inc.peca_required:
            peca_open += 1
    if peca_open > 0:
        score += 15
    return min(score, 100)


def risk_level(score: int) -> str:
    if score <= 25:
        return "Low"
    elif score <= 50:
        return "Medium"
    elif score <= 75:
        return "High"
    return "Critical"


@router.get("/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    open_statuses = ["new", "investigating", "contained", "recovering"]

    # Open incidents
    open_incidents = db.query(Incident).filter(Incident.status.in_(open_statuses)).all()
    open_counts = defaultdict(int)
    for inc in open_incidents:
        open_counts[inc.severity] += 1

    # Incidents last 30 days
    since = datetime.utcnow() - timedelta(days=30)
    recent_count = db.query(Incident).filter(Incident.created_at >= since).count()

    # Incidents by type
    all_incidents = db.query(Incident).all()
    by_type = defaultdict(int)
    for inc in all_incidents:
        by_type[inc.incident_type or "other"] += 1

    # Incidents by month (last 6 months)
    by_month = []
    for i in range(5, -1, -1):
        month_start = (datetime.utcnow().replace(day=1) - timedelta(days=30 * i)).replace(day=1, hour=0, minute=0, second=0)
        month_end = (month_start + timedelta(days=32)).replace(day=1)
        count = db.query(Incident).filter(
            Incident.created_at >= month_start,
            Incident.created_at < month_end,
        ).count()
        by_month.append({"month": month_start.strftime("%b %Y"), "count": count})

    # IOC stats
    active_iocs = db.query(IOC).filter(IOC.status == "active").count()
    malicious_iocs = db.query(IOC).filter(IOC.verdict == "malicious").count()
    suspicious_iocs = db.query(IOC).filter(IOC.verdict == "suspicious").count()

    # TI checks today
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    ti_today = db.query(TICache).filter(TICache.created_at >= today_start).count()

    # Risk score
    score = calculate_risk_score(open_incidents)

    # PECA open
    peca_open = sum(1 for inc in open_incidents if inc.peca_required)

    # Recent incidents
    recent_incidents = (
        db.query(Incident).order_by(Incident.created_at.desc()).limit(5).all()
    )

    # Recent TI checks
    recent_ti = (
        db.query(TICache).order_by(TICache.created_at.desc()).limit(5).all()
    )

    return {
        "open_incidents": {
            "total": len(open_incidents),
            "critical": open_counts.get("critical", 0),
            "high": open_counts.get("high", 0),
            "medium": open_counts.get("medium", 0),
            "low": open_counts.get("low", 0),
        },
        "incidents_last_30_days": recent_count,
        "incidents_by_type": dict(by_type),
        "incidents_by_month": by_month,
        "active_iocs": {
            "total": active_iocs,
            "malicious": malicious_iocs,
            "suspicious": suspicious_iocs,
        },
        "ti_checks_today": ti_today,
        "risk_score": score,
        "risk_level": risk_level(score),
        "peca_required_open": peca_open,
        "recent_incidents": [
            {"id": inc.id, "title": inc.title, "severity": inc.severity, "status": inc.status,
             "incident_type": inc.incident_type, "created_at": inc.created_at.isoformat()}
            for inc in recent_incidents
        ],
        "recent_ti_checks": [
            {"id": t.id, "indicator": t.indicator, "indicator_type": t.indicator_type,
             "verdict": t.verdict, "created_at": t.created_at.isoformat()}
            for t in recent_ti
        ],
    }
