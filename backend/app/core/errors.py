"""Domain errors mapped to HTTP responses with understandable messages."""
from __future__ import annotations


class AppError(Exception):
    status_code = 400
    code = "bad_request"

    def __init__(self, message: str, *, details: dict | None = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class NotFound(AppError):
    status_code = 404
    code = "not_found"


class Forbidden(AppError):
    status_code = 403
    code = "forbidden"


class Conflict(AppError):
    status_code = 409
    code = "conflict"


class Unsupported(AppError):
    """The target device/driver does not support the requested operation."""
    status_code = 422
    code = "unsupported_operation"


class ValidationFailed(AppError):
    status_code = 422
    code = "validation_failed"


class DeviceConnectionError(AppError):
    status_code = 502
    code = "device_connection_failed"
