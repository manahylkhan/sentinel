import hashlib
import os
from pathlib import Path

from fastapi import UploadFile
from sqlalchemy.orm import Session

from models import CustodyLog, Evidence

VAULT_DIR = Path("evidence_files")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


async def save_evidence(
    file: UploadFile,
    incident_id: str,
    description: str,
    uploaded_by: str,
    db: Session,
) -> dict:
    content = await file.read()
    file_hash = _sha256(content)

    # Save file
    incident_dir = VAULT_DIR / incident_id
    incident_dir.mkdir(parents=True, exist_ok=True)
    file_path = incident_dir / file.filename
    file_path.write_bytes(content)

    evidence = Evidence(
        incident_id=incident_id,
        file_name=file.filename,
        file_path=str(file_path),
        file_hash_sha256=file_hash,
        file_size=len(content),
        description=description,
        uploaded_by=uploaded_by,
    )
    db.add(evidence)
    db.commit()
    db.refresh(evidence)

    # Chain of custody: upload entry
    log = CustodyLog(
        evidence_id=evidence.id,
        action="uploaded",
        performed_by=uploaded_by,
        notes=f"File uploaded: {file.filename} ({len(content)} bytes)",
    )
    db.add(log)
    db.commit()

    return {
        "id": evidence.id,
        "file_name": evidence.file_name,
        "file_hash_sha256": evidence.file_hash_sha256,
        "file_size": evidence.file_size,
        "description": evidence.description,
        "uploaded_by": evidence.uploaded_by,
        "created_at": evidence.created_at.isoformat(),
    }


def log_access(evidence_id: str, performed_by: str, action: str, db: Session):
    log = CustodyLog(
        evidence_id=evidence_id,
        action=action,
        performed_by=performed_by,
    )
    db.add(log)
    db.commit()
