"""Application configuration.

All configuration comes from environment variables (populated by the installer into
/opt/infrapilot/config/infrapilot.env). Nothing secret is hard-coded in source.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="IP_", env_file=None, extra="ignore")

    app_name: str = "InfraPilot"
    app_version: str = "1.1.1"
    # production: no simulated devices may be created; demo: simulated devices allowed and flagged
    app_mode: Literal["production", "demo"] = Field("production", validation_alias=AliasChoices("IP_APP_MODE", "IP_MODE"))
    base_url: str = Field("https://localhost", validation_alias=AliasChoices("IP_BASE_URL", "IP_PUBLIC_URL"))

    database_url: str = Field(
        default="sqlite:///./infrapilot-dev.db",
        description="SQLAlchemy URL, e.g. mssql+pyodbc://user:pass@mssql:1433/InfraPilot?driver=ODBC+Driver+18+for+SQL+Server&TrustServerCertificate=yes",
    )
    # Optional: read the DB password from a Docker secret and substitute "{password}" in database_url
    database_password_file: str | None = None
    db_pool_size: int = 10
    db_echo: bool = False

    # Vault master key: 32 bytes, base64. Read from file in production (docker secret).
    vault_key_file: str | None = None
    vault_master_key: str | None = None

    session_ttl_minutes: int = 480
    session_idle_minutes: int = 60
    cookie_secure: bool = True
    cookie_name: str = "ip_session"

    lockout_threshold: int = 5
    lockout_minutes: int = 15
    password_min_length: int = 12

    rate_limit_login_per_minute: int = 10
    rate_limit_api_per_minute: int = 600

    allowed_origins: list[str] = []

    worker_poll_seconds: float = 2.0
    worker_concurrency: int = 4
    monitoring_interval_seconds: int = Field(120, validation_alias=AliasChoices("IP_MONITORING_INTERVAL_SECONDS", "IP_MONITOR_INTERVAL_SECONDS"))
    default_job_timeout_seconds: int = 900
    operation_timeout_seconds: int = 60

    ansible_work_dir: str = "/var/lib/infrapilot/ansible"
    playbook_dir: str = "/app/playbooks"

    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_starttls: bool = True
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from: str = "infrapilot@localhost"

    log_level: str = "INFO"

    # Host folders the containers can write device backups into (same path inside and outside the container,
    # bind-mounted in docker-compose.yml). Colon-separated. Settings -> Backup -> "Folder on the server" must be under one.
    export_roots: str = "/srv/infrapilot-exports:/mnt:/media"


    def resolved_database_url(self) -> str:
        url = self.database_url
        if "{password}" in url:
            if not self.database_password_file:
                raise RuntimeError("database_url contains {password} but IP_DATABASE_PASSWORD_FILE is not set")
            from urllib.parse import quote_plus
            with open(self.database_password_file, encoding="utf-8") as fh:
                url = url.replace("{password}", quote_plus(fh.read().strip()))
        return with_mars(url)


def with_mars(url: str) -> str:
    """SQL Server: enable Multiple Active Result Sets.

    Without MARS a connection can only have one open result set, and any code path that runs a query
    while another query's rows are still being read fails with "Connection is busy with results for
    another command". MARS is supported by every SQL Server version InfraPilot targets and ODBC Driver 18.
    """
    if not url.startswith("mssql+pyodbc") or "mars_connection" in url.lower():
        return url
    return url + ("&" if "?" in url else "?") + "MARS_Connection=yes"


@lru_cache
def get_settings() -> Settings:
    return Settings()
