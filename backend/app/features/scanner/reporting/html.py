# backend/app/features/scanner/reporting/html.py
"""HTML report generator using Jinja2 templates."""

import webbrowser
from pathlib import Path
from typing import Dict

from jinja2 import Environment, FileSystemLoader

from backend.app.core import logs
from ..models import ScanResult, Severity


def generate_html_report(result: ScanResult, output_path: str = "report.html") -> str:
    """
    Generate HTML report from scan result.

    Args:
        result: ScanResult object containing scan findings
        output_path: Path to save the HTML report

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

    # Render template
    html = template.render(
        result=result,
        has_vulnerabilities=len(result.vulnerabilities) > 0,
        severity_counts=severity_counts,
        total_vulnerabilities=len(result.vulnerabilities),
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
