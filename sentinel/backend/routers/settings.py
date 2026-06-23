from pathlib import Path

from fastapi import APIRouter
from pydantic import BaseModel

from modules.notifications.email_notifier import send_test_email

router = APIRouter(prefix="/api/settings", tags=["settings"])

ENV_PATH = Path(".env")


class SettingsUpdate(BaseModel):
    ANTHROPIC_API_KEY: str | None = None
    ABUSEIPDB_API_KEY: str | None = None
    VIRUSTOTAL_API_KEY: str | None = None
    OTX_API_KEY: str | None = None
    IPINFO_API_KEY: str | None = None
    SHODAN_API_KEY: str | None = None
    ALERT_EMAIL: str | None = None
    ORG_NAME: str | None = None
    ORG_TYPE: str | None = None
    SMTP_HOST: str | None = None
    SMTP_PORT: int | None = None
    SMTP_USER: str | None = None
    SMTP_PASSWORD: str | None = None


def _read_env() -> dict:
    env = {}
    if ENV_PATH.exists():
        for line in ENV_PATH.read_text().splitlines():
            line = line.strip()
            if line and "=" in line and not line.startswith("#"):
                key, _, value = line.partition("=")
                env[key.strip()] = value.strip()
    return env


def _write_env(env: dict):
    lines = [f"{k}={v}" for k, v in env.items()]
    ENV_PATH.write_text("\n".join(lines) + "\n")


@router.get("")
def get_settings():
    env = _read_env()
    # Mask sensitive values
    masked = {}
    sensitive = {"ANTHROPIC_API_KEY", "ABUSEIPDB_API_KEY", "VIRUSTOTAL_API_KEY",
                 "OTX_API_KEY", "IPINFO_API_KEY", "SHODAN_API_KEY", "SMTP_PASSWORD"}
    for k, v in env.items():
        if k in sensitive and v:
            masked[k] = v[:4] + "..." + v[-4:] if len(v) > 8 else "***"
        else:
            masked[k] = v
    return masked


@router.post("")
def save_settings(update: SettingsUpdate):
    env = _read_env()
    data = update.model_dump(exclude_none=True)
    for k, v in data.items():
        if v is not None:
            env[k] = str(v)
    _write_env(env)

    # Reload settings in running app
    from config import settings
    for k, v in data.items():
        if hasattr(settings, k):
            setattr(settings, k, v)

    return {"saved": True}


@router.post("/test-email")
async def test_email():
    result = await send_test_email()
    if result:
        return {"sent": True, "message": "Test email sent successfully"}
    return {"sent": False, "message": "Failed to send — check SMTP configuration in settings"}
