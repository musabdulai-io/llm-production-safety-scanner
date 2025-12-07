# backend/app/features/scanner/reporting/html.py
"""HTML report generator using Jinja2 templates."""

import webbrowser
from pathlib import Path
from typing import Dict, List

from jinja2 import Environment, FileSystemLoader

from backend.app.core import logs
from backend.app.core.config import settings
from ..models import ScanResult, Severity, AttackResult

# Sorting orders
STATUS_ORDER = {"FAIL": 0, "ERROR": 1, "PASS": 2}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def calculate_score(severity_counts: Dict[str, int]) -> int:
    """Calculate security score (0-100) based on vulnerability severities.

    Formula: 100 - (critical*25 + high*15 + medium*5 + low*2)
    """
    deductions = (
        severity_counts.get("CRITICAL", 0) * 25 +
        severity_counts.get("HIGH", 0) * 15 +
        severity_counts.get("MEDIUM", 0) * 5 +
        severity_counts.get("LOW", 0) * 2
    )
    return max(0, 100 - deductions)


def generate_html_report(
    result: ScanResult,
    output_path: str = "report.html",
    verbose: bool = False,
) -> str:
    """
    Generate HTML report from scan result.

    Args:
        result: ScanResult object containing scan findings
        output_path: Path to save the HTML report
        verbose: Include raw request/response logs in report

    Returns:
        Absolute path to the generated report file
    """
    logs.info(f"Generating HTML report", "reporting", {"output": output_path})

    # Get template directory (backend/templates/)
    template_dir = Path(__file__).parent.parent.parent.parent.parent / "templates"

    env = Environment(loader=FileSystemLoader(template_dir))
    template = env.get_template("report.html")

    # Calculate severity counts
    severity_counts: Dict[str, int] = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }
    for vuln in result.vulnerabilities:
        severity_counts[vuln.severity.value] += 1

    # Calculate security score
    score = calculate_score(severity_counts)

    # Group attack results by category
    security_attacks: List[AttackResult] = []
    reliability_attacks: List[AttackResult] = []
    cost_attacks: List[AttackResult] = []

    for attack in result.attack_results:
        category = getattr(attack, "category", None)
        if category:
            cat_value = category.value if hasattr(category, "value") else str(category)
        else:
            cat_value = "security"

        if cat_value == "security":
            security_attacks.append(attack)
        elif cat_value == "reliability":
            reliability_attacks.append(attack)
        elif cat_value == "cost":
            cost_attacks.append(attack)
        else:
            security_attacks.append(attack)

    # Sort attacks: FAIL first, then ERROR, then PASS
    security_attacks.sort(key=lambda x: STATUS_ORDER.get(x.status, 3))
    reliability_attacks.sort(key=lambda x: STATUS_ORDER.get(x.status, 3))
    cost_attacks.sort(key=lambda x: STATUS_ORDER.get(x.status, 3))

    # Count passed attacks
    passed_count = sum(1 for attack in result.attack_results if attack.status == "PASS")

    # Group vulnerabilities by attack category
    security_vulns = []
    reliability_vulns = []
    cost_vulns = []

    # Create a mapping of attack type to category
    attack_category_map = {}
    for attack in result.attack_results:
        category = getattr(attack, "category", None)
        if category:
            cat_value = category.value if hasattr(category, "value") else str(category)
        else:
            cat_value = "security"
        attack_category_map[attack.attack_type] = cat_value

    # Categorize vulnerabilities based on which attack found them
    for vuln in result.vulnerabilities:
        # Try to determine category from vulnerability name
        vuln_category = "security"  # default
        for attack_type, category in attack_category_map.items():
            if attack_type.lower() in vuln.name.lower():
                vuln_category = category
                break

        if vuln_category == "reliability":
            reliability_vulns.append(vuln)
        elif vuln_category == "cost":
            cost_vulns.append(vuln)
        else:
            security_vulns.append(vuln)

    # Sort vulnerabilities by severity: CRITICAL first
    security_vulns.sort(key=lambda x: SEVERITY_ORDER.get(x.severity.value, 4))
    reliability_vulns.sort(key=lambda x: SEVERITY_ORDER.get(x.severity.value, 4))
    cost_vulns.sort(key=lambda x: SEVERITY_ORDER.get(x.severity.value, 4))

    # All vulnerabilities sorted by severity for Critical Findings section
    all_vulns = sorted(result.vulnerabilities, key=lambda x: SEVERITY_ORDER.get(x.severity.value, 4))
    total_vulns = len(result.vulnerabilities)

    # Render template
    html = template.render(
        # Metadata
        target_url=result.target_url,
        scan_id=result.scan_id,
        timestamp=result.timestamp,
        duration=result.duration_seconds,

        # Scorecard (score removed - now just vuln counts)
        total_vulns=total_vulns,
        all_vulns=all_vulns,
        critical_count=severity_counts["CRITICAL"],
        high_count=severity_counts["HIGH"],
        medium_count=severity_counts["MEDIUM"],
        low_count=severity_counts["LOW"],
        passed_count=passed_count,

        # Backward compatibility
        result=result,
        has_vulnerabilities=total_vulns > 0,
        severity_counts=severity_counts,
        total_vulnerabilities=total_vulns,

        # CTA
        cta_url=settings.CTA_URL,
        cta_text=settings.CTA_TEXT,

        # Categorized & sorted data
        security_attacks=security_attacks,
        reliability_attacks=reliability_attacks,
        cost_attacks=cost_attacks,
        security_vulns=security_vulns,
        reliability_vulns=reliability_vulns,
        cost_vulns=cost_vulns,
        security_vuln_count=len(security_vulns),
        reliability_vuln_count=len(reliability_vulns),
        cost_vuln_count=len(cost_vulns),

        # Verbose mode
        include_raw_log=verbose,
        raw_log=result.raw_log if verbose else [],
    )

    # Write to file
    output_file = Path(output_path).absolute()
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)

    logs.info(f"Report generated", "reporting", {"path": str(output_file)})
    return str(output_file)


def open_report(path: str) -> None:
    """
    Open the HTML report in the default web browser.

    Args:
        path: Path to the HTML report file
    """
    file_url = f"file://{Path(path).absolute()}"
    logs.debug(f"Opening report in browser", "reporting", {"url": file_url})
    webbrowser.open(file_url)
