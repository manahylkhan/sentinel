from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, Response
from sqlalchemy.orm import Session

from database import get_db
from models import CustodyLog, Evidence, Incident, IncidentTimeline
from modules.evidence.report_generator import generate_fir_report
from modules.evidence.vault import log_access, save_evidence

router = APIRouter(prefix="/api", tags=["evidence"])


def serialize_evidence(ev: Evidence) -> dict:
    return {
        "id": ev.id,
        "incident_id": ev.incident_id,
        "file_name": ev.file_name,
        "file_hash_sha256": ev.file_hash_sha256,
        "file_size": ev.file_size,
        "description": ev.description,
        "uploaded_by": ev.uploaded_by,
        "created_at": ev.created_at.isoformat() if ev.created_at else None,
    }


@router.post("/incidents/{incident_id}/evidence")
async def upload_evidence(
    incident_id: str,
    description: str = Form(""),
    uploaded_by: str = Form("Unknown"),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    result = await save_evidence(file, incident_id, description, uploaded_by, db)

    tl = IncidentTimeline(
        incident_id=incident_id,
        action="Evidence Uploaded",
        detail=f"{uploaded_by} uploaded file: {file.filename}",
        created_by=uploaded_by,
    )
    db.add(tl)
    db.commit()

    return result


@router.get("/incidents/{incident_id}/evidence")
def list_evidence(incident_id: str, db: Session = Depends(get_db)):
    evidence = db.query(Evidence).filter(Evidence.incident_id == incident_id).all()
    return [serialize_evidence(e) for e in evidence]


@router.get("/evidence/{evidence_id}/download")
def download_evidence(evidence_id: str, accessed_by: str = "unknown", db: Session = Depends(get_db)):
    ev = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found")

    path = Path(ev.file_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="File not found on disk")

    log_access(evidence_id, accessed_by, "accessed", db)
    return FileResponse(path=str(path), filename=ev.file_name)


@router.delete("/evidence/{evidence_id}")
def delete_evidence(evidence_id: str, deleted_by: str = "unknown", db: Session = Depends(get_db)):
    ev = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found")

    log_access(evidence_id, deleted_by, "deleted", db)

    path = Path(ev.file_path)
    if path.exists():
        path.unlink()

    db.delete(ev)
    db.commit()
    return {"deleted": True}


@router.get("/incidents/{incident_id}/report/pdf")
def generate_report(incident_id: str, db: Session = Depends(get_db)):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    timeline = [
        {"action": t.action, "detail": t.detail, "created_by": t.created_by, "created_at": t.created_at.isoformat()}
        for t in sorted(inc.timeline, key=lambda x: x.created_at)
    ]
    iocs = [
        {"indicator": i.indicator, "indicator_type": i.indicator_type, "verdict": i.verdict, "status": i.status}
        for i in inc.iocs
    ]
    evidence = [
        {"file_name": e.file_name, "file_size": e.file_size, "file_hash_sha256": e.file_hash_sha256,
         "uploaded_by": e.uploaded_by, "created_at": e.created_at.isoformat()}
        for e in inc.evidence
    ]

    inc_dict = {
        "id": inc.id, "title": inc.title, "description": inc.description,
        "incident_type": inc.incident_type, "severity": inc.severity, "status": inc.status,
        "affected_systems": inc.affected_systems, "reporter_name": inc.reporter_name,
        "reporter_email": inc.reporter_email, "peca_required": inc.peca_required,
        "peca_reason": inc.peca_reason, "created_at": inc.created_at.isoformat() if inc.created_at else None,
        "mitre_techniques": inc.mitre_techniques,
    }

    pdf_bytes = generate_fir_report(inc_dict, timeline, iocs, evidence)

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="SENTINEL_Report_{incident_id[:8]}.pdf"'},
    )
