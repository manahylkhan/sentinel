import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db
from models import Incident, Playbook
from modules.playbooks.builtin_loader import get_builtin_playbooks

router = APIRouter(prefix="/api/playbooks", tags=["playbooks"])


class PlaybookCreate(BaseModel):
    name: str
    incident_type: str
    description: str = ""
    content_json: str


class PlaybookUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    content_json: str | None = None


def serialize_playbook(pb: Playbook) -> dict:
    content = {}
    try:
        content = json.loads(pb.content_json) if pb.content_json else {}
    except Exception:
        pass
    phases = content.get("phases", [])
    step_count = sum(len(p.get("steps", [])) for p in phases)
    return {
        "id": pb.id,
        "name": pb.name,
        "incident_type": pb.incident_type,
        "description": pb.description,
        "is_builtin": pb.is_builtin,
        "phase_count": len(phases),
        "step_count": step_count,
        "content": content,
        "created_at": pb.created_at.isoformat() if pb.created_at else None,
    }


def ensure_builtins(db: Session):
    count = db.query(Playbook).filter(Playbook.is_builtin == True).count()
    if count == 0:
        for pb_data in get_builtin_playbooks():
            content = {k: v for k, v in pb_data.items() if k not in ("name", "incident_type", "description")}
            pb = Playbook(
                name=pb_data["name"],
                incident_type=pb_data["incident_type"],
                description=pb_data.get("description", ""),
                content_json=json.dumps(content),
                is_builtin=True,
            )
            db.add(pb)
        db.commit()


@router.get("")
def list_playbooks(db: Session = Depends(get_db)):
    ensure_builtins(db)
    playbooks = db.query(Playbook).order_by(Playbook.is_builtin.desc(), Playbook.name).all()
    return [serialize_playbook(pb) for pb in playbooks]


@router.get("/{playbook_id}")
def get_playbook(playbook_id: str, db: Session = Depends(get_db)):
    pb = db.query(Playbook).filter(Playbook.id == playbook_id).first()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return serialize_playbook(pb)


@router.post("")
def create_playbook(req: PlaybookCreate, db: Session = Depends(get_db)):
    # Validate JSON
    try:
        json.loads(req.content_json)
    except Exception:
        raise HTTPException(status_code=400, detail="content_json must be valid JSON")
    pb = Playbook(
        name=req.name,
        incident_type=req.incident_type,
        description=req.description,
        content_json=req.content_json,
        is_builtin=False,
    )
    db.add(pb)
    db.commit()
    db.refresh(pb)
    return serialize_playbook(pb)


@router.put("/{playbook_id}")
def update_playbook(playbook_id: str, update: PlaybookUpdate, db: Session = Depends(get_db)):
    pb = db.query(Playbook).filter(Playbook.id == playbook_id).first()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    if pb.is_builtin:
        raise HTTPException(status_code=400, detail="Cannot edit built-in playbooks")
    if update.name:
        pb.name = update.name
    if update.description is not None:
        pb.description = update.description
    if update.content_json:
        try:
            json.loads(update.content_json)
        except Exception:
            raise HTTPException(status_code=400, detail="content_json must be valid JSON")
        pb.content_json = update.content_json
    db.commit()
    return serialize_playbook(pb)


@router.delete("/{playbook_id}")
def delete_playbook(playbook_id: str, db: Session = Depends(get_db)):
    pb = db.query(Playbook).filter(Playbook.id == playbook_id).first()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    if pb.is_builtin:
        raise HTTPException(status_code=400, detail="Cannot delete built-in playbooks")
    db.delete(pb)
    db.commit()
    return {"deleted": True}


@router.post("/{playbook_id}/apply/{incident_id}")
def apply_playbook(playbook_id: str, incident_id: str, db: Session = Depends(get_db)):
    pb = db.query(Playbook).filter(Playbook.id == playbook_id).first()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    inc.ai_playbook = pb.content_json
    db.commit()
    return {"applied": True, "playbook_name": pb.name}
