from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from database import Base, engine
from routers import dashboard, evidence, incidents, iocs, logs, playbooks, settings, threat_intel

# Create all DB tables
Base.metadata.create_all(bind=engine)

# Ensure evidence directory exists
Path("evidence_files").mkdir(exist_ok=True)

app = FastAPI(
    title="SENTINEL",
    description="AI-Powered Incident Response + Threat Intelligence Platform",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(threat_intel.router)
app.include_router(incidents.router)
app.include_router(iocs.router)
app.include_router(logs.router)
app.include_router(evidence.router)
app.include_router(playbooks.router)
app.include_router(dashboard.router)
app.include_router(settings.router)


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "SENTINEL"}


@app.on_event("startup")
async def startup_event():
    # Pre-load built-in playbooks on first run
    from database import SessionLocal
    from routers.playbooks import ensure_builtins
    db = SessionLocal()
    try:
        ensure_builtins(db)
    finally:
        db.close()
