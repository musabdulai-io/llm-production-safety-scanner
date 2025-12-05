# backend/app/core/observability.py
"""Structured logging client for AI Security Scanner."""

import logging
import sys
from typing import Any, Dict, Optional

from .config import settings


class LoggingClient:
    """Structured logging client."""

    def __init__(self) -> None:
        self._logger = logging.getLogger(settings.APP_NAME)
        self._configure_logger()

    def _configure_logger(self) -> None:
        """Configure the logger with appropriate handlers and formatters."""
        self._logger.setLevel(logging.DEBUG if settings.DEBUG else logging.INFO)
        self._logger.handlers.clear()

        handler = logging.StreamHandler(sys.stdout)

        # Debug: simple format, Prod: JSON format
        if settings.DEBUG:
            formatter = logging.Formatter(
                "%(asctime)s | %(levelname)-8s | %(message)s",
                datefmt="%H:%M:%S",
            )
        else:
            formatter = logging.Formatter(
                '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "message": "%(message)s"}',
                datefmt="%Y-%m-%dT%H:%M:%S",
            )

        handler.setFormatter(formatter)
        self._logger.addHandler(handler)

    def _format_message(
        self,
        message: str,
        component: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Format log message with component and metadata."""
        parts = [f"[{component}] {message}"]
        if metadata:
            meta_str = " ".join(f"{k}={v}" for k, v in metadata.items())
            parts.append(f"| {meta_str}")
        return " ".join(parts)

    def debug(
        self,
        message: str,
        component: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log debug message."""
        self._logger.debug(self._format_message(message, component, metadata))

    def info(
        self,
        message: str,
        component: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log info message."""
        self._logger.info(self._format_message(message, component, metadata))

    def warning(
        self,
        message: str,
        component: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log warning message."""
        self._logger.warning(self._format_message(message, component, metadata))

    def error(
        self,
        message: str,
        component: str,
        exception: Optional[Exception] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log error message with optional exception details."""
        meta = metadata.copy() if metadata else {}
        if exception:
            meta["error"] = str(exception)
            meta["error_type"] = type(exception).__name__
        self._logger.error(self._format_message(message, component, meta))

    def security(
        self,
        message: str,
        event_type: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log security event."""
        meta = metadata.copy() if metadata else {}
        meta["event_type"] = event_type
        self._logger.warning(self._format_message(message, "security", meta))


# Global logging instance
logs = LoggingClient()
