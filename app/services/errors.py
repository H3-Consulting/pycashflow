"""Transport-neutral service errors.

Each error carries a stable machine-readable ``code`` so the REST layer and the
MCP layer can map it to their own envelopes without string matching.
"""

from __future__ import annotations


class ServiceError(Exception):
    """Base class for expected, user-facing service failures."""

    code = "service_error"

    def __init__(self, message: str, *, details: dict | None = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def to_dict(self) -> dict:
        body = {"code": self.code, "message": self.message}
        if self.details:
            body["details"] = self.details
        return body


class ValidationFailed(ServiceError):
    """One or more input fields are invalid."""

    code = "validation_error"

    def __init__(self, fields: dict[str, str], message: str = "Validation failed"):
        super().__init__(message, details={"fields": fields})
        self.fields = fields


class NotFound(ServiceError):
    """The record does not exist within the caller's account."""

    code = "not_found"


class Forbidden(ServiceError):
    """The authenticated principal may not perform this action."""

    code = "forbidden"


class Conflict(ServiceError):
    """The change conflicts with current state (duplicate, stale version)."""

    code = "conflict"


class ClarificationRequired(ServiceError):
    """The request is ambiguous; the caller must choose between options."""

    code = "clarification_required"
