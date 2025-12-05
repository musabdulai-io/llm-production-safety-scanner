# backend/app/features/scanner/routes.py
"""FastAPI routes for the scanner API."""

import asyncio
import json
import time
import uuid
from collections import defaultdict
from typing import Any, AsyncGenerator, Dict
from urllib.parse import urlparse

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from sse_starlette.sse import EventSourceResponse

from backend.app.core import (
    RateLimitError,
    SandboxViolationError,
    logs,
    settings,
)
from .schemas import ScanStartRequest, ScanStartResponse, ScanStatusResponse
from .services import ScannerService

router = APIRouter(prefix="/scanner", tags=["scanner"])

# In-memory rate limiting (per IP)
rate_limit_store: Dict[str, list] = defaultdict(list)

# In-memory scan storage with TTL
scan_results: Dict[str, Dict[str, Any]] = {}
SCAN_TTL_SECONDS = 3600  # 1 hour


async def cleanup_old_scans() -> None:
    """Remove scan results older than TTL. Run as background task."""
    while True:
        await asyncio.sleep(300)  # Run every 5 minutes
        now = time.time()
        expired = [
            scan_id
            for scan_id, data in scan_results.items()
            if now - data.get("created_at", now) > SCAN_TTL_SECONDS
        ]
        for scan_id in expired:
            del scan_results[scan_id]
        if expired:
            logs.info(f"Cleaned up {len(expired)} expired scans", "cleanup")


def get_client_ip(request: Request) -> str:
    """Get real client IP, handling reverse proxies."""
    # Check X-Forwarded-For (take first IP - original client)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()

    # Check X-Real-IP
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()

    # Fallback to direct connection
    return request.client.host if request.client else "unknown"


def check_rate_limit(client_ip: str) -> None:
    """
    Check if client has exceeded rate limit.

    Raises:
        RateLimitError: If rate limit exceeded
    """
    now = time.time()
    window_start = now - settings.RATE_LIMIT_WINDOW

    # Clean old requests
    rate_limit_store[client_ip] = [
        ts for ts in rate_limit_store[client_ip] if ts > window_start
    ]

    if len(rate_limit_store[client_ip]) >= settings.RATE_LIMIT_REQUESTS:
        logs.security(
            "Rate limit exceeded",
            "rate_limit",
            {"ip": client_ip, "requests": len(rate_limit_store[client_ip])},
        )
        raise RateLimitError("Rate limit exceeded. Please wait 5 minutes.")

    rate_limit_store[client_ip].append(now)


def validate_sandbox_url(target_url: str) -> None:
    """
    Validate target URL is the allowed sandbox using proper URL parsing.

    Raises:
        SandboxViolationError: If target is not the sandbox
    """
    sandbox_parsed = urlparse(settings.SANDBOX_URL)
    target_parsed = urlparse(target_url)

    # Must use http or https
    if target_parsed.scheme not in ("http", "https"):
        logs.security(
            "Invalid URL scheme",
            "sandbox_block",
            {"target": target_url, "scheme": target_parsed.scheme},
        )
        raise SandboxViolationError()

    # Must match exact hostname
    if target_parsed.netloc != sandbox_parsed.netloc:
        logs.security(
            "Sandbox violation attempt",
            "sandbox_block",
            {"target": target_url, "allowed": settings.SANDBOX_URL},
        )
        raise SandboxViolationError()


@router.post("/scan/start", response_model=ScanStartResponse)
async def start_scan(
    request: ScanStartRequest,
    http_request: Request,
    background_tasks: BackgroundTasks,
) -> ScanStartResponse:
    """
    Start a new security scan.

    This endpoint:
    1. Validates the target URL is the allowed sandbox
    2. Checks rate limits
    3. Starts the scan in a background task
    4. Returns a scan_id for tracking progress
    """
    client_ip = get_client_ip(http_request)

    logs.info(
        "Scan request received",
        "api",
        {"target": request.target_url, "client_ip": client_ip},
    )

    # Web mode: validate sandbox URL
    validate_sandbox_url(request.target_url)

    # Rate limiting
    check_rate_limit(client_ip)

    # Generate scan ID and initialize storage with TTL tracking
    scan_id = str(uuid.uuid4())
    scan_results[scan_id] = {
        "status": "running",
        "logs": [],
        "result": None,
        "error": None,
        "created_at": time.time(),
    }

    async def run_scan() -> None:
        """Execute the scan in background."""
        scanner = ScannerService()

        def on_progress(message: str) -> None:
            scan_results[scan_id]["logs"].append(message)

        try:
            result = await scanner.scan(
                target_url=request.target_url,
                fast=request.fast,
                headers=request.headers,
                on_progress=on_progress,
            )
            scan_results[scan_id]["status"] = "completed"
            scan_results[scan_id]["result"] = result.model_dump(mode="json")

        except Exception as e:
            logs.error("Scan failed", "api", exception=e)
            scan_results[scan_id]["status"] = "failed"
            scan_results[scan_id]["error"] = str(e)

    background_tasks.add_task(run_scan)

    logs.info("Scan started", "api", {"scan_id": scan_id})
    return ScanStartResponse(scan_id=scan_id, message="Scan started")


@router.get("/scan/{scan_id}/stream")
async def stream_scan(scan_id: str) -> EventSourceResponse:
    """
    Stream scan progress via Server-Sent Events.

    Events:
    - type: "log" - Progress log messages
    - type: "result" - Final scan result (JSON)
    - type: "error" - Error message if scan failed
    """
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")

    async def event_generator() -> AsyncGenerator[dict, None]:
        """Generate SSE events for scan progress."""
        last_log_index = 0

        while True:
            scan = scan_results[scan_id]

            # Send new log lines
            new_logs = scan["logs"][last_log_index:]
            for log_message in new_logs:
                yield {
                    "event": "message",
                    "data": json.dumps({"type": "log", "message": log_message}),
                }
            last_log_index = len(scan["logs"])

            # Check completion
            if scan["status"] == "completed":
                yield {
                    "event": "message",
                    "data": json.dumps({"type": "result", "data": scan["result"]}),
                }
                break
            elif scan["status"] == "failed":
                yield {
                    "event": "message",
                    "data": json.dumps(
                        {"type": "error", "message": scan.get("error", "Scan failed")}
                    ),
                }
                break

            await asyncio.sleep(0.5)

    return EventSourceResponse(event_generator())


@router.get("/scan/{scan_id}/status", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str) -> ScanStatusResponse:
    """Get the current status of a scan."""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan = scan_results[scan_id]

    # Calculate progress based on logs
    log_count = len(scan["logs"])
    # Rough estimate: 3 attacks * ~10 steps each
    progress = min(int((log_count / 30) * 100), 99)
    if scan["status"] == "completed":
        progress = 100
    elif scan["status"] == "failed":
        progress = 0

    # Extract current attack from logs
    current_attack = None
    for log in reversed(scan["logs"]):
        if "[INFO] Running" in log:
            current_attack = log.split("Running ")[-1].replace("...", "")
            break

    return ScanStatusResponse(
        scan_id=scan_id,
        status=scan["status"],
        progress=progress,
        current_attack=current_attack,
    )


@router.get("/scan/{scan_id}/result")
async def get_scan_result(scan_id: str) -> Dict[str, Any]:
    """Get the final scan result."""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan = scan_results[scan_id]

    if scan["status"] == "running":
        raise HTTPException(status_code=202, detail="Scan still in progress")

    if scan["status"] == "failed":
        raise HTTPException(status_code=500, detail=scan.get("error", "Scan failed"))

    return scan["result"]
