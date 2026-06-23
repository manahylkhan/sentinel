from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    ANTHROPIC_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""
    OTX_API_KEY: str = ""
    IPINFO_API_KEY: str = ""
    SHODAN_API_KEY: str = ""
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    ALERT_EMAIL: str = ""
    ORG_NAME: str = "My Organization"
    ORG_TYPE: str = "SME"
    DATABASE_URL: str = "sqlite:///./sentinel.db"

    class Config:
        env_file = ".env"
        extra = "allow"


settings = Settings()
