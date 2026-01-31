"""Audit logging for security-relevant operations.

Logs all authentication and authorization events, as well as
resource creation/modification operations.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from fastapi import Request

log = logging.getLogger("audit")


@dataclass
class AuditEvent:
    """Structured audit event."""

    action: str  # e.g., "auth.success", "identity.create"
    principal: str = "anonymous"  # key_id or "anonymous"
    resource: str | None = None  # e.g., AID, registry_key, SAID
    status: str = "success"  # "success", "denied", "error", "revoked"
    details: dict[str, Any] | None = None  # Additional context
    request_id: str | None = None  # Correlation ID
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class AuditLogger:
    """Audit logger for security operations.

    Logs events as structured JSON to stdout via Python's logging module.
    """

    def __init__(self, enabled: bool = True):
        """Initialize the audit logger.

        Args:
            enabled: Whether audit logging is enabled
        """
        self.enabled = enabled

    def log(self, event: AuditEvent) -> None:
        """Write an audit event to the log.

        Args:
            event: The audit event to log
        """
        if not self.enabled:
            return

        extra = {
            "type": "audit",
            "principal": event.principal,
            "action": event.action,
            "status": event.status,
        }

        if event.resource:
            extra["resource"] = event.resource

        if event.request_id:
            extra["request_id"] = event.request_id

        if event.details:
            extra["details"] = event.details

        # Use appropriate log level based on status
        if event.status in ("denied", "revoked", "error"):
            log.warning(f"audit: {event.action} {event.status}", extra=extra)
        else:
            log.info(f"audit: {event.action} {event.status}", extra=extra)

    def log_auth_success(
        self,
        principal_id: str,
        request: Request | None = None,
    ) -> None:
        """Log a successful authentication."""
        self.log(
            AuditEvent(
                action="auth.success",
                principal=principal_id,
                status="success",
                request_id=_get_request_id(request),
            )
        )

    def log_auth_failure(
        self,
        reason: str = "invalid",
        request: Request | None = None,
    ) -> None:
        """Log a failed authentication attempt."""
        self.log(
            AuditEvent(
                action="auth.failure",
                principal="anonymous",
                status="denied",
                details={"reason": reason},
                request_id=_get_request_id(request),
            )
        )

    def log_auth_revoked(
        self,
        principal_id: str,
        request: Request | None = None,
    ) -> None:
        """Log an authentication attempt with a revoked key."""
        self.log(
            AuditEvent(
                action="auth.revoked",
                principal=principal_id,
                status="revoked",
                request_id=_get_request_id(request),
            )
        )

    def log_auth_reload(
        self,
        principal_id: str,
        key_count: int,
        request: Request | None = None,
    ) -> None:
        """Log an API key config reload."""
        self.log(
            AuditEvent(
                action="auth.reload",
                principal=principal_id,
                status="success",
                details={"key_count": key_count},
                request_id=_get_request_id(request),
            )
        )

    def log_access(
        self,
        action: str,
        principal_id: str,
        resource: str | None = None,
        status: str = "success",
        details: dict[str, Any] | None = None,
        request: Request | None = None,
    ) -> None:
        """Log a resource access event.

        Args:
            action: Action name (e.g., "identity.create", "registry.read")
            principal_id: The authenticated principal's key_id
            resource: Resource identifier (AID, registry key, SAID)
            status: "success", "denied", or "error"
            details: Additional context
            request: Optional request for correlation ID
        """
        self.log(
            AuditEvent(
                action=action,
                principal=principal_id,
                resource=resource,
                status=status,
                details=details,
                request_id=_get_request_id(request),
            )
        )


def _get_request_id(request: Request | None) -> str | None:
    """Extract request ID from request headers if available."""
    if request is None:
        return None

    # Common request ID headers
    for header in ("X-Request-ID", "X-Correlation-ID", "Request-Id"):
        if header in request.headers:
            return request.headers[header]

    return None


# Global logger instance
_audit_logger: AuditLogger | None = None


def get_audit_logger() -> AuditLogger:
    """Get the global audit logger instance."""
    global _audit_logger

    if _audit_logger is None:
        from app.config import AUTH_ENABLED

        _audit_logger = AuditLogger(enabled=AUTH_ENABLED)

    return _audit_logger


def reset_audit_logger() -> None:
    """Reset the global logger (for testing)."""
    global _audit_logger
    _audit_logger = None
