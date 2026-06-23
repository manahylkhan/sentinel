import asyncio
import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from config import settings
from database import get_db
from models import IOC
from modules.iocs.stix_export import export_to_stix
from modules.threat_intel.ai_verdict import generate_verdict
from modules.threat_intel.cache import get_cached_result, save_to_cache
from modules.threat_intel.feeds import check_all_feeds

router = APIRouter(prefix="/api/iocs", tags=["iocs"])


class IOCCreate(BaseModel):
    indicator: str
    indicator_type: str
    severity: str = "medium"
    notes: str = ""
    incident_id: str | None = None


class IOCUpdate(BaseModel):
    status: str | None = None
    severity: str | None = None
    notes: str | None = None
    verdict: str | None = None


def serialize_ioc(ioc: IOC) -> dict:
    return {
        "id": ioc.id,
        "indicator": ioc.indicator,
        "indicator_type": ioc.indicator_type,
        "verdict": ioc.verdict,
        "severity": ioc.severity,
        "source": ioc.source,
        "status": ioc.status,
        "incident_id": ioc.incident_id,
        "notes": ioc.notes,
        "created_at": ioc.created_at.isoformat() if ioc.created_at else None,
    }


@router.get("")
def list_iocs(
    ioc_type: str | None = None,
    status: str | None = None,
    severity: str | None = None,
    verdict: str | None = None,
    db: Session = Depends(get_db),
):
    q = db.query(IOC)
    if ioc_type:
        q = q.filter(IOC.indicator_type == ioc_type)
    if status:
        q = q.filter(IOC.status == status)
    if severity:
        q = q.filter(IOC.severity == severity)
    if verdict:
        q = q.filter(IOC.verdict == verdict)
    iocs = q.order_by(IOC.created_at.desc()).all()
    return [serialize_ioc(i) for i in iocs]


@router.post("")
def create_ioc(req: IOCCreate, db: Session = Depends(get_db)):
    existing = db.query(IOC).filter(IOC.indicator == req.indicator).first()
    if existing:
        raise HTTPException(status_code=400, detail="IOC already exists")
    ioc = IOC(
        indicator=req.indicator,
        indicator_type=req.indicator_type,
        severity=req.severity,
        notes=req.notes,
        incident_id=req.incident_id,
        source="manual",
        status="active",
    )
    db.add(ioc)
    db.commit()
    db.refresh(ioc)
    return serialize_ioc(ioc)


@router.patch("/{ioc_id}")
def update_ioc(ioc_id: str, update: IOCUpdate, db: Session = Depends(get_db)):
    ioc = db.query(IOC).filter(IOC.id == ioc_id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    if update.status:
        ioc.status = update.status
    if update.severity:
        ioc.severity = update.severity
    if update.notes is not None:
        ioc.notes = update.notes
    if update.verdict:
        ioc.verdict = update.verdict
    db.commit()
    return serialize_ioc(ioc)


@router.delete("/{ioc_id}")
def delete_ioc(ioc_id: str, db: Session = Depends(get_db)):
    ioc = db.query(IOC).filter(IOC.id == ioc_id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    db.delete(ioc)
    db.commit()
    return {"deleted": True}


@router.post("/bulk-check")
async def bulk_check_iocs(db: Session = Depends(get_db)):
    """Re-check all active IOCs against TI feeds."""
    active_iocs = db.query(IOC).filter(IOC.status == "active").all()

    updated = []
    for ioc in active_iocs:
        cached = get_cached_result(db, ioc.indicator)
        if cached:
            ioc.verdict = cached["verdict"]
        else:
            feed_data = await check_all_feeds(ioc.indicator, ioc.indicator_type, settings)
            ai_result = await generate_verdict(ioc.indicator, feed_data)
            ioc.verdict = ai_result["verdict"]
            save_to_cache(
                db=db,
                indicator=ioc.indicator,
                indicator_type=ioc.indicator_type,
                feed_results=feed_data["feed_results"],
                verdict=ai_result["verdict"],
                ai_summary=ai_result["summary"],
                ai_action=ai_result["recommended_action"],
                confidence=ai_result["confidence"],
                flagged_by=feed_data["flagged_by"],
            )
        db.commit()
        updated.append({"indicator": ioc.indicator, "verdict": ioc.verdict})

    return {"updated": len(updated), "results": updated}


@router.get("/export/stix")
def export_stix(db: Session = Depends(get_db)):
    iocs = db.query(IOC).all()
    ioc_list = [serialize_ioc(i) for i in iocs]
    stix_json = export_to_stix(ioc_list)
    return Response(
        content=stix_json,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=sentinel_iocs.stix.json"},
    )


@router.get("/stats")
def ioc_stats(db: Session = Depends(get_db)):
    total = db.query(IOC).count()
    active = db.query(IOC).filter(IOC.status == "active").count()
    blocked = db.query(IOC).filter(IOC.status == "blocked").count()
    malicious = db.query(IOC).filter(IOC.verdict == "malicious").count()
    return {"total": total, "active": active, "blocked": blocked, "malicious": malicious}
