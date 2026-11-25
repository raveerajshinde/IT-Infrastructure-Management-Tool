"""E-mail notifications (SMTP settings from system settings; password from the vault)."""
from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage

from sqlalchemy.orm import Session

from app.services import settings_store

log = logging.getLogger("infrapilot.notify")


def smtp_config(db: Session) -> dict:
    return settings_store.smtp_config(db)


def send_email(db: Session, to: list[str] | str, subject: str, body: str, attachments: list[tuple[str, bytes, str]] | None = None) -> tuple[bool, str]:
    cfg = smtp_config(db)
    if not cfg.get("enabled") or not cfg.get("host"):
        return False, "SMTP is not configured"
    rcpts = [x.strip() for x in (to.split(",") if isinstance(to, str) else to) if x and x.strip()]
    if not rcpts:
        return False, "No recipients"
    msg = EmailMessage()
    msg["From"] = cfg.get("from_address") or "infrapilot@localhost"
    msg["To"] = ", ".join(rcpts)
    msg["Subject"] = subject[:200]
    msg.set_content(body)
    for name, data, mime in attachments or []:
        maintype, _, subtype = mime.partition("/")
        msg.add_attachment(data, maintype=maintype or "application", subtype=subtype or "octet-stream", filename=name)
    try:
        port = int(cfg.get("port") or 587)
        if port == 465:
            server = smtplib.SMTP_SSL(cfg["host"], port, timeout=20, context=ssl.create_default_context())
        else:
            server = smtplib.SMTP(cfg["host"], port, timeout=20)
            if cfg.get("starttls", True):
                server.starttls(context=ssl.create_default_context())
        with server:
            if cfg.get("username"):
                server.login(cfg["username"], cfg.get("password", ""))
            server.send_message(msg)
        return True, "sent"
    except Exception as exc:  # report, never crash the caller
        log.warning("SMTP send failed: %s", exc)
        return False, str(exc)
