"""Audit logging for SIP redirect service.

Sprint 42: Structured audit logging for INVITE requests.
Sprint 44: Added ring buffer for status endpoint visibility.
"""

import json
import logging
import os
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from app.config import AUDIT_LOG_DIR

log = logging.getLogger(__name__)


class AuditLogger:
    """Structured audit logger for SIP events.

    Logs to both standard logging, a dedicated audit file, and an
    in-memory ring buffer for status endpoint visibility.
    """

    MAX_BUFFER_SIZE = 1000  # Store last 1000 events

    def __init__(self, service_name: str = "sip-redirect"):
        """Initialize audit logger.

        Args:
            service_name: Service identifier for log entries
        """
        self._service = service_name
        self._file_handler: Optional[logging.FileHandler] = None
        self._buffer: deque[dict] = deque(maxlen=self.MAX_BUFFER_SIZE)
        self._start_time = time.time()
        self._setup_file_logging()

    def _setup_file_logging(self) -> None:
        """Set up file-based audit logging."""
        try:
            # Create audit log directory if it doesn't exist
            AUDIT_LOG_DIR.mkdir(parents=True, exist_ok=True)

            # Create dated audit log file
            date_str = datetime.now().strftime("%Y-%m-%d")
            log_file = AUDIT_LOG_DIR / f"audit-{date_str}.jsonl"

            self._file_handler = logging.FileHandler(log_file)
            self._file_handler.setLevel(logging.INFO)
            self._file_handler.setFormatter(logging.Formatter("%(message)s"))

            log.info(f"Audit logging to {log_file}")

        except Exception as e:
            log.warning(f"Failed to set up audit file logging: {e}")
            self._file_handler = None

    def log(
        self,
        action: str,
        details: Optional[dict[str, Any]] = None,
        api_key_prefix: Optional[str] = None,
        call_id: Optional[str] = None,
        from_tn: Optional[str] = None,
        to_tn: Optional[str] = None,
        status_code: Optional[int] = None,
        vvp_status: Optional[str] = None,
    ) -> None:
        """Log an audit event.

        Args:
            action: Action identifier (e.g., "invite.received", "invite.completed")
            details: Additional event details
            api_key_prefix: First 8 chars of API key (for identification)
            call_id: SIP Call-ID
            from_tn: Originating phone number
            to_tn: Destination phone number
            status_code: SIP response status code
            vvp_status: VVP verification status
        """
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "service": self._service,
            "action": action,
        }

        if api_key_prefix:
            entry["api_key_prefix"] = api_key_prefix
        if call_id:
            entry["call_id"] = call_id
        if from_tn:
            entry["from_tn"] = from_tn
        if to_tn:
            entry["to_tn"] = to_tn
        if status_code is not None:
            entry["status_code"] = status_code
        if vvp_status:
            entry["vvp_status"] = vvp_status
        if details:
            entry["details"] = details

        json_entry = json.dumps(entry)

        # Store in ring buffer
        self._buffer.append(entry)

        # Log to standard logging
        log.info(f"AUDIT: {json_entry}")

        # Log to audit file
        if self._file_handler:
            try:
                record = logging.LogRecord(
                    name="audit",
                    level=logging.INFO,
                    pathname="",
                    lineno=0,
                    msg=json_entry,
                    args=(),
                    exc_info=None,
                )
                self._file_handler.emit(record)
            except Exception as e:
                log.warning(f"Failed to write audit log: {e}")

    def get_recent_events(
        self,
        limit: int = 100,
        action_filter: Optional[str] = None,
        since_timestamp: Optional[datetime] = None,
    ) -> list[dict]:
        """Get recent audit events from buffer.

        Args:
            limit: Max events to return
            action_filter: Filter by action prefix (e.g., "invite.")
            since_timestamp: Only return events after this time

        Returns:
            List of audit event dicts, newest first
        """
        events = list(self._buffer)
        events.reverse()  # Newest first

        if action_filter:
            events = [e for e in events if e.get("action", "").startswith(action_filter)]

        if since_timestamp:
            cutoff = since_timestamp.isoformat()
            events = [e for e in events if e.get("timestamp", "") >= cutoff]

        return events[:limit]

    def get_call_summary(self, minutes: int = 10) -> dict:
        """Get summary of recent calls.

        Args:
            minutes: Look back period in minutes

        Returns:
            Summary dict with counts by status code
        """
        cutoff = datetime.now(timezone.utc).timestamp() - (minutes * 60)
        by_status: dict[int, int] = {}
        total = 0
        success = 0
        errors = 0

        for event in self._buffer:
            # Parse timestamp
            ts_str = event.get("timestamp", "")
            if ts_str:
                try:
                    ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    if ts.timestamp() < cutoff:
                        continue
                except ValueError:
                    continue

            status = event.get("status_code")
            if status is not None:
                total += 1
                by_status[status] = by_status.get(status, 0) + 1
                if status == 302:
                    success += 1
                elif status >= 400:
                    errors += 1

        return {
            "total_calls": total,
            "success_count": success,
            "error_count": errors,
            "by_status": by_status,
        }

    def get_buffer_stats(self) -> dict:
        """Get buffer statistics.

        Returns:
            Dict with buffer_size, max_buffer_size, uptime_seconds
        """
        return {
            "buffer_size": len(self._buffer),
            "max_buffer_size": self.MAX_BUFFER_SIZE,
            "uptime_seconds": time.time() - self._start_time,
        }


# Global audit logger instance
_audit_logger: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    """Get or create the global audit logger."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger
