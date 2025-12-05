# backend/app/features/scanner/services.py
"""Scanner service - orchestrates security scanning attacks."""

import uuid
from datetime import datetime
from typing import Callable, List, Optional

import httpx

from backend.app.core import logs, settings
from .attacks import AttackModule, PIILeaker, PromptInjector, RAGPoisoner
from .models import AttackResult, ScanResult, Vulnerability


class ScannerService:
    """Orchestrates security scanning attacks."""

    def __init__(self) -> None:
        """Initialize scanner with attack modules."""
        self.attacks: List[AttackModule] = [
            PromptInjector(),
            RAGPoisoner(),
            PIILeaker(),
        ]

    async def scan(
        self,
        target_url: str,
        fast: bool = False,
        headers: Optional[dict] = None,
        on_progress: Optional[Callable[[str], None]] = None,
    ) -> ScanResult:
        """
        Execute a full security scan against the target.

        Args:
            target_url: Target LLM/RAG endpoint URL
            fast: If True, skip slow tests (RAG poisoning)
            headers: Optional custom headers for requests
            on_progress: Optional callback for progress updates

        Returns:
            ScanResult with all findings
        """
        scan_id = str(uuid.uuid4())
        start_time = datetime.utcnow()

        logs.info(
            f"Starting scan {scan_id}",
            "scanner",
            {"target": target_url, "fast": fast},
        )

        if on_progress:
            on_progress(f"[INFO] Initializing scan {scan_id[:8]}...")
            on_progress(f"[INFO] Target: {target_url}")

        attack_results: List[AttackResult] = []
        all_vulnerabilities: List[Vulnerability] = []
        all_raw_logs: List[dict] = []

        async with httpx.AsyncClient(
            timeout=settings.REQUEST_TIMEOUT,
            follow_redirects=True,
        ) as client:
            for attack in self.attacks:
                # Skip RAG poisoning in fast mode
                if fast and attack.name == "RAG Poisoning":
                    if on_progress:
                        on_progress(f"[SKIP] Skipping {attack.name} (fast mode)")
                    continue

                if on_progress:
                    on_progress(f"[INFO] Running {attack.name}...")

                try:
                    result = await attack.execute(client, target_url, headers)
                    attack_results.append(result)
                    all_vulnerabilities.extend(result.vulnerabilities)
                    all_raw_logs.extend(result.raw_log)

                    status_msg = "VULNERABLE" if result.vulnerabilities else "PASS"
                    if on_progress:
                        on_progress(
                            f"[{'FAIL' if result.vulnerabilities else 'PASS'}] "
                            f"{attack.name}: {status_msg} ({result.latency_ms}ms)"
                        )

                except Exception as e:
                    logs.error(
                        f"Attack {attack.name} failed",
                        "scanner",
                        exception=e,
                    )
                    if on_progress:
                        on_progress(f"[ERROR] {attack.name}: {str(e)}")

                    # Record error as attack result
                    attack_results.append(
                        AttackResult(
                            attack_type=attack.name,
                            status="ERROR",
                            latency_ms=0,
                            vulnerabilities=[],
                            raw_log=[{"error": str(e)}],
                        )
                    )

        duration = (datetime.utcnow() - start_time).total_seconds()

        # Determine overall status
        if all_vulnerabilities:
            status = "FAILED"
        elif any(r.status == "ERROR" for r in attack_results):
            status = "PARTIAL"
        else:
            status = "SUCCESS"

        if on_progress:
            vuln_count = len(all_vulnerabilities)
            on_progress(f"[INFO] Scan complete in {duration:.2f}s")
            if vuln_count > 0:
                on_progress(f"[WARN] Found {vuln_count} vulnerabilities!")
            else:
                on_progress("[INFO] No vulnerabilities detected.")

        logs.info(
            f"Completed scan {scan_id}",
            "scanner",
            {
                "status": status,
                "vulnerabilities": len(all_vulnerabilities),
                "duration": f"{duration:.2f}s",
            },
        )

        return ScanResult(
            target_url=target_url,
            scan_id=scan_id,
            timestamp=start_time,
            duration_seconds=duration,
            status=status,
            vulnerabilities=all_vulnerabilities,
            attack_results=attack_results,
            raw_log=all_raw_logs,
        )
