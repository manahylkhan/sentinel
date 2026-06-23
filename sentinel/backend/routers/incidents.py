import json
from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db
from models import IOC, Incident, IncidentTimeline
from modules.incidents.classifier import classify_incident
from modules.incidents.ioc_extractor import extract_iocs_from_text
from modules.incidents.mitre_mapper import map_to_mitre
from modules.incidents.playbook import generate_playbook
from modules.notifications.email_notifier import send_critical_alert, send_peca_reminder

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


# ── Pydantic models ───────────────────────────────────────────────────────────

class NewIncidentRequest(BaseModel):
    title: str
    description: str
    affected_systems: str = ""
    reporter_name: str
    reporter_email: str


class StatusUpdate(BaseModel):
    status: str


class TimelineEntry(BaseModel):
    action: str
    detail: str = ""
    created_by: str


# ── Serializers ───────────────────────────────────────────────────────────────

def serialize_incident(inc: Incident) -> dict:
    return {
        "id": inc.id,
        "title": inc.title,
        "description": inc.description,
        "incident_type": inc.incident_type,
        "severity": inc.severity,
        "status": inc.status,
        "affected_systems": inc.affected_systems,
        "reporter_name": inc.reporter_name,
        "reporter_email": inc.reporter_email,
        "ai_playbook": json.loads(inc.ai_playbook) if inc.ai_playbook else None,
        "ai_classification": json.loads(inc.ai_classification) if inc.ai_classification else None,
        "mitre_techniques": json.loads(inc.mitre_techniques) if inc.mitre_techniques else [],
        "peca_required": inc.peca_required,
        "peca_reason": inc.peca_reason,
        "created_at": inc.created_at.isoformat() if inc.created_at else None,
        "updated_at": inc.updated_at.isoformat() if inc.updated_at else None,
        "closed_at": inc.closed_at.isoformat() if inc.closed_at else None,
        "ioc_count": len(inc.iocs) if inc.iocs else 0,
        "evidence_count": len(inc.evidence) if inc.evidence else 0,
    }


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("")
async def create_incident(req: NewIncidentRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    # 1. Create incident
    incident = Incident(
        title=req.title,
        description=req.description,
        affected_systems=req.affected_systems,
        reporter_name=req.reporter_name,
        reporter_email=req.reporter_email,
        status="new",
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)

    # 2. AI Classification
    classification = await classify_incident(req.description, req.affected_systems)
    incident.incident_type = classification.get("incident_type", "other")
    incident.severity = classification.get("severity", "medium")
    incident.ai_classification = json.dumps(classification)
    incident.peca_required = classification.get("peca_reporting_required", False)
    incident.peca_reason = classification.get("peca_reason", "")

    # 3. Generate playbook
    playbook = await generate_playbook(
        incident.incident_type,
        incident.severity,
        req.description,
        req.affected_systems,
    )
    incident.ai_playbook = json.dumps(playbook)

    # 4. MITRE ATT&CK mapping
    mitre = await map_to_mitre(incident.incident_type, req.description)
    incident.mitre_techniques = json.dumps(mitre)

    db.commit()

    # 5. Extract and save IOCs
    iocs = await extract_iocs_from_text(req.description + " " + req.affected_systems)
    for ioc_item in iocs:
        existing = db.query(IOC).filter(IOC.indicator == ioc_item["value"]).first()
        if not existing:
            ioc = IOC(
                indicator=ioc_item["value"],
                indicator_type=ioc_item["type"],
                source="incident_extract",
                incident_id=incident.id,
                severity="medium",
                status="active",
            )
            db.add(ioc)
    db.commit()

    # 6. First timeline entry
    timeline = IncidentTimeline(
        incident_id=incident.id,
        action="Incident Reported",
        detail=f"Incident reported by {req.reporter_name} ({req.reporter_email})",
        created_by=req.reporter_name,
    )
    db.add(timeline)
    db.commit()
    db.refresh(incident)

    # 7. Send notifications in background
    inc_dict = serialize_incident(incident)
    if incident.severity == "critical":
        background_tasks.add_task(send_critical_alert, inc_dict)
    if incident.peca_required:
        background_tasks.add_task(send_peca_reminder, inc_dict)

    return serialize_incident(incident)


@router.get("")
def list_incidents(
    status: str | None = None,
    severity: str | None = None,
    incident_type: str | None = None,
    db: Session = Depends(get_db),
):
    q = db.query(Incident)
    if status:
        q = q.filter(Incident.status == status)
    if severity:
        q = q.filter(Incident.severity == severity)
    if incident_type:
        q = q.filter(Incident.incident_type == incident_type)
    incidents = q.order_by(Incident.created_at.desc()).all()
    return [serialize_incident(i) for i in incidents]


@router.get("/{incident_id}")
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    data = serialize_incident(inc)
    data["iocs"] = [
        {"id": ioc.id, "indicator": ioc.indicator, "type": ioc.indicator_type,
         "verdict": ioc.verdict, "severity": ioc.severity, "status": ioc.status}
        for ioc in inc.iocs
    ]
    return data


@router.patch("/{incident_id}/status")
def update_status(incident_id: str, update: StatusUpdate, db: Session = Depends(get_db)):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    valid = ["new", "investigating", "contained", "recovering", "closed"]
    if update.status not in valid:
        raise HTTPException(status_code=400, detail=f"Status must be one of: {valid}")
    inc.status = update.status
    if update.status == "closed":
        inc.closed_at = datetime.utcnow()
    inc.updated_at = datetime.utcnow()
    db.commit()
    return {"status": inc.status}


@router.post("/{incident_id}/timeline")
def add_timeline(incident_id: str, entry: TimelineEntry, db: Session = Depends(get_db)):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    tl = IncidentTimeline(
        incident_id=incident_id,
        action=entry.action,
        detail=entry.detail,
        created_by=entry.created_by,
    )
    db.add(tl)
    inc.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(tl)
    return {"id": tl.id, "action": tl.action, "detail": tl.detail,
            "created_by": tl.created_by, "created_at": tl.created_at.isoformat()}


@router.get("/{incident_id}/timeline")
def get_timeline(incident_id: str, db: Session = Depends(get_db)):
    entries = (
        db.query(IncidentTimeline)
        .filter(IncidentTimeline.incident_id == incident_id)
        .order_by(IncidentTimeline.created_at.asc())
        .all()
    )
    return [
        {"id": e.id, "action": e.action, "detail": e.detail,
         "created_by": e.created_by, "created_at": e.created_at.isoformat()}
        for e in entries
    ]
