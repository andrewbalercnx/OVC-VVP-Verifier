"""Audit logging for security-relevant operations.

Logs all authentication and authorization events, as well as
resource creation/modification operations.
"""

import logging
from collections import deque
from dataclasses import asdict, dataclass, field
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
    Also maintains an in-memory ring buffer for recent event retrieval.
    """

    MAX_BUFFER_SIZE = 1000  # Store last 1000 events

    def __init__(self, enabled: bool = True):
        """Initialize the audit logger.

        Args:
            enabled: Whether audit logging is enabled
        """
        self.enabled = enabled
        self._buffer: deque[dict] = deque(maxlen=self.MAX_BUFFER_SIZE)

    def log(
        self,
        event: AuditEvent | None = None,
        *,
        action: str | None = None,
        principal: str | None = None,
        resource: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        status: str = "success",
        details: dict[str, Any] | None = None,
        request_id: str | None = None,
    ) -> None:
        """Write an audit event to the log.

        Accepts either an AuditEvent object or keyword arguments.

        Args:
            event: AuditEvent object (optional)
            action: Action name if not using event object
            principal: Principal ID if not using event object
            resource: Resource identifier if not using event object
            resource_type: Resource type (combined with resource_id if provided)
            resource_id: Resource ID (combined with resource_type if provided)
            status: Status string (default: "success")
            details: Additional context dict
            request_id: Correlation ID
        """
        if not self.enabled:
            return

        # Build event from kwargs if not provided
        if event is None:
            # Combine resource_type and resource_id if both provided
            combined_resource = resource
            if resource_type and resource_id:
                combined_resource = f"{resource_type}:{resource_id}"
            elif resource_type:
                combined_resource = resource_type

            event = AuditEvent(
                action=action or "unknown",
                principal=principal or "anonymous",
                resource=combined_resource,
                status=status,
                details=details,
                request_id=request_id,
            )

        # Store in ring buffer
        self._buffer.append(asdict(event))

        # Build extra dict for structured logging
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

    def get_recent_events(
        self,
        limit: int = 100,
        action_filter: str | None = None,
        status_filter: str | None = None,
    ) -> list[dict]:
        """Get recent audit events from buffer.

        Args:
            limit: Max events to return
            action_filter: Filter by action prefix (e.g., "auth.")
            status_filter: Filter by status (e.g., "denied")

        Returns:
            List of audit event dicts, newest first
        """
        events = list(self._buffer)
        events.reverse()  # Newest first

        if action_filter:
            events = [e for e in events if e["action"].startswith(action_filter)]
        if status_filter:
            events = [e for e in events if e["status"] == status_filter]

        return events[:limit]

    def get_buffer_stats(self) -> dict:
        """Get buffer statistics.

        Returns:
            Dict with buffer_size, max_buffer_size
        """
        return {
            "buffer_size": len(self._buffer),
            "max_buffer_size": self.MAX_BUFFER_SIZE,
        }

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
