# backend/app/features/scanner/schemas.py
"""API request/response schemas for the scanner."""

from typing import Dict, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator

# Allowed headers for scan requests (security whitelist)
ALLOWED_HEADERS = {
    "authorization",
    "x-api-key",
    "content-type",
    "accept",
    "user-agent",
    "x-request-id",
}


class ScanStartRequest(BaseModel):
    """Request to start a new security scan."""

    target_url: str = Field(
        ..., min_length=1, max_length=2048, description="Target LLM/RAG endpoint URL"
    )
    fast: bool = Field(default=False, description="Skip RAG upload tests")
    headers: Optional[Dict[str, str]] = Field(
        default=None, description="Custom headers for requests"
    )

    @field_validator("target_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        """Validate URL format and scheme."""
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https"):
            raise ValueError("URL must use http or https scheme")
        if not parsed.netloc:
            raise ValueError("Invalid URL format - missing host")
        return v

    @field_validator("headers")
    @classmethod
    def validate_headers(cls, v: Optional[Dict[str, str]]) -> Optional[Dict[str, str]]:
        """Validate headers are in allowlist and not too long."""
        if v is None:
            return v
        for key, value in v.items():
            if key.lower() not in ALLOWED_HEADERS:
                raise ValueError(f"Header '{key}' not allowed")
            if len(value) > 4096:
                raise ValueError(f"Header '{key}' value too long (max 4096 chars)")
        return v


class ScanStartResponse(BaseModel):
    """Response after starting a scan."""

    scan_id: str
    message: str = "Scan started"


class ScanStatusResponse(BaseModel):
    """Response for scan status queries."""

    scan_id: str
    status: str  # "running", "completed", "failed"
    progress: int  # 0-100
    current_attack: Optional[str] = None
