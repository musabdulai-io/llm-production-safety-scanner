# backend/app/core/exceptions.py
"""Custom exception hierarchy for AI Security Scanner."""

from typing import Any, Dict, Optional


class AppException(Exception):
    """Base exception for application errors."""

    def __init__(
        self,
        message: str,
        status_code: int = 500,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.message = message
        self.status_code = status_code
        self.details = details or {}
        super().__init__(message)


class ValidationError(AppException):
    """Raised when input validation fails."""

    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, status_code=400, details=details)


class SecurityError(AppException):
    """Raised when a security violation is detected."""

    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, status_code=403, details=details)


class RateLimitError(AppException):
    """Raised when rate limit is exceeded."""

    def __init__(self, message: str = "Rate limit exceeded") -> None:
        super().__init__(message, status_code=429)


class SandboxViolationError(SecurityError):
    """Raised when attempting to scan non-sandbox targets in demo mode."""

    def __init__(
        self, message: str = "Demo mode: Only sandbox target allowed"
    ) -> None:
        super().__init__(message, details={"guard": "sandbox"})


class ScanError(AppException):
    """Raised when a scan operation fails."""

    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, status_code=500, details=details)


class TargetConnectionError(AppException):
    """Raised when unable to connect to target URL."""

    def __init__(
        self,
        message: str = "Unable to connect to target",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, status_code=502, details=details)
