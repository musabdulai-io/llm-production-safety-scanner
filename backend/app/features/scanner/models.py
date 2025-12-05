# backend/app/features/scanner/models.py
"""Data models for the security scanner."""

from datetime import datetime
from enum import Enum
from typing import List, Literal

from pydantic import BaseModel


class Severity(str, Enum):
    """Vulnerability severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Vulnerability(BaseModel):
    """A detected security vulnerability."""

    name: str  # e.g., "System Prompt Leakage"
    severity: Severity
    description: str
    remediation: str  # Code snippet or advice
    evidence_request: str  # The prompt we sent
    evidence_response: str  # The AI response that triggered detection


class AttackResult(BaseModel):
    """Result of a single attack module execution."""

    attack_type: str
    status: Literal["PASS", "FAIL", "ERROR"]
    latency_ms: int
    vulnerabilities: List[Vulnerability]
    raw_log: List[dict]  # Request/response pairs


class ScanResult(BaseModel):
    """Complete scan result aggregating all attack results."""

    target_url: str
    scan_id: str
    timestamp: datetime
    duration_seconds: float
    status: Literal["SUCCESS", "FAILED", "PARTIAL"]
    vulnerabilities: List[Vulnerability]
    attack_results: List[AttackResult]
    raw_log: List[dict]  # Full chat history for replay
