from datetime import datetime, timezone


def utcnow() -> datetime:
    """Naive UTC timestamp (stored as DATETIME2 on SQL Server)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)
