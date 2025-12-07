# backend/app/features/scanner/reporting/console.py
"""Rich terminal UI for CLI output."""

from typing import List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from backend.app.core.config import settings
from ..models import AttackResult, ScanResult

# Global console instance
console = Console()

# Sorting orders
STATUS_ORDER = {"FAIL": 0, "ERROR": 1, "PASS": 2}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def show_progress(message: str) -> None:
    """Show a progress message in the terminal."""
    # Color code based on message type - emphasize failures
    if "[FAIL]" in message or "[ERROR]" in message or "[WARN]" in message:
        console.print(f"[bold red]{message}[/bold red]")
    elif "[PASS]" in message:
        console.print(f"[dim green]{message}[/dim green]")  # De-emphasized
    elif "[SKIP]" in message:
        console.print(f"[yellow]{message}[/yellow]")
    else:
        console.print(f"[cyan]{message}[/cyan]")


def _create_attack_table(title: str, results: List[AttackResult]) -> Table:
    """Create a table for a category of attacks."""
    # Count failures for title
    fail_count = sum(1 for r in results if r.status == "FAIL")
    title_style = "bold red" if fail_count > 0 else "bold cyan"
    title_suffix = f" ({fail_count} issues)" if fail_count > 0 else ""

    table = Table(title=f"{title}{title_suffix}", show_header=True, header_style="bold cyan", title_style=title_style)

    table.add_column("Attack Type", style="cyan", width=25)
    table.add_column("Status", justify="center", width=10)
    table.add_column("Issues", justify="center", width=8)
    table.add_column("Latency", justify="right", width=10)

    for result in results:
        # Determine status style - emphasize failures, de-emphasize passes
        if result.status == "PASS":
            status_display = "[dim green]PASS[/dim green]"
            attack_style = "dim"
        elif result.status == "FAIL":
            status_display = "[bold red]FAIL[/bold red]"
            attack_style = "bold white"
        else:
            status_display = "[yellow]ERROR[/yellow]"
            attack_style = "yellow"

        # Vulnerability count with color
        vuln_count = len(result.vulnerabilities)
        if vuln_count > 0:
            vuln_display = f"[bold red]{vuln_count}[/bold red]"
        else:
            vuln_display = "[dim]0[/dim]"

        table.add_row(
            f"[{attack_style}]{result.attack_type}[/{attack_style}]",
            status_display,
            vuln_display,
            f"{result.latency_ms}ms",
        )

    return table


def show_attack_table(results: List[AttackResult]) -> None:
    """Display attack results in formatted tables grouped by category."""
    # Group by category
    security_attacks = []
    reliability_attacks = []
    cost_attacks = []

    for result in results:
        category = getattr(result, "category", None)
        if category:
            cat_value = category.value if hasattr(category, "value") else str(category)
        else:
            cat_value = "security"

        if cat_value == "security":
            security_attacks.append(result)
        elif cat_value == "reliability":
            reliability_attacks.append(result)
        elif cat_value == "cost":
            cost_attacks.append(result)
        else:
            security_attacks.append(result)

    # Sort attacks: FAIL first, then ERROR, then PASS
    security_attacks.sort(key=lambda x: STATUS_ORDER.get(x.status, 3))
    reliability_attacks.sort(key=lambda x: STATUS_ORDER.get(x.status, 3))
    cost_attacks.sort(key=lambda x: STATUS_ORDER.get(x.status, 3))

    console.print()

    # Security attacks
    if security_attacks:
        table = _create_attack_table("Security Attacks", security_attacks)
        console.print(table)
        console.print()

    # Reliability attacks
    if reliability_attacks:
        table = _create_attack_table("Reliability Tests", reliability_attacks)
        console.print(table)
        console.print()

    # Cost attacks
    if cost_attacks:
        table = _create_attack_table("Cost & Performance", cost_attacks)
        console.print(table)


def show_failures_summary(result: ScanResult) -> None:
    """Show prominent failures summary at the top before category tables."""
    if not result.vulnerabilities:
        return

    vuln_count = len(result.vulnerabilities)

    # Count by severity
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    severity_vulns: dict = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}

    for vuln in result.vulnerabilities:
        sev = vuln.severity.value
        severity_counts[sev] += 1
        severity_vulns[sev].append(vuln.name)

    # Build content for panel
    lines = [f"[bold red]{vuln_count} VULNERABILITIES FOUND[/bold red]\n"]

    severity_colors = {
        "CRITICAL": "red",
        "HIGH": "orange1",
        "MEDIUM": "yellow",
        "LOW": "blue",
    }

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if severity_counts[sev] > 0:
            color = severity_colors[sev]
            lines.append(f"[{color}]{sev} ({severity_counts[sev]})[/{color}]")
            for name in severity_vulns[sev]:
                lines.append(f"  [{color}]• {name}[/{color}]")
            lines.append("")

    content = "\n".join(lines)

    panel = Panel(
        content,
        border_style="red",
        title="[bold red]⚠️  VULNERABILITIES DETECTED[/bold red]",
        title_align="left",
    )

    console.print()
    console.print(panel)


def show_summary(result: ScanResult) -> None:
    """Show the final scan summary panel."""
    vuln_count = len(result.vulnerabilities)

    # Count by severity
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for vuln in result.vulnerabilities:
        severity_counts[vuln.severity.value] += 1

    # Count by category
    security_count = 0
    reliability_count = 0
    cost_count = 0

    # Build category mapping from attack results
    attack_category_map = {}
    for attack in result.attack_results:
        category = getattr(attack, "category", None)
        if category:
            cat_value = category.value if hasattr(category, "value") else str(category)
        else:
            cat_value = "security"
        attack_category_map[attack.attack_type] = cat_value

    for vuln in result.vulnerabilities:
        vuln_category = "security"
        for attack_type, category in attack_category_map.items():
            if attack_type.lower() in vuln.name.lower():
                vuln_category = category
                break

        if vuln_category == "reliability":
            reliability_count += 1
        elif vuln_category == "cost":
            cost_count += 1
        else:
            security_count += 1

    if vuln_count > 0:
        # Build severity breakdown
        severity_lines = []
        if severity_counts["CRITICAL"]:
            severity_lines.append(f"[red]CRITICAL: {severity_counts['CRITICAL']}[/red]")
        if severity_counts["HIGH"]:
            severity_lines.append(f"[orange1]HIGH: {severity_counts['HIGH']}[/orange1]")
        if severity_counts["MEDIUM"]:
            severity_lines.append(f"[yellow]MEDIUM: {severity_counts['MEDIUM']}[/yellow]")
        if severity_counts["LOW"]:
            severity_lines.append(f"[blue]LOW: {severity_counts['LOW']}[/blue]")

        severity_str = "  ".join(severity_lines) if severity_lines else ""

        # Build category breakdown
        category_lines = []
        if security_count:
            category_lines.append(f"Security: {security_count}")
        if reliability_count:
            category_lines.append(f"Reliability: {reliability_count}")
        if cost_count:
            category_lines.append(f"Cost: {cost_count}")
        category_str = "  |  ".join(category_lines) if category_lines else ""

        content = (
            f"[bold red]{vuln_count} ISSUES FOUND[/bold red]\n\n"
            f"{severity_str}\n"
            f"{category_str}\n\n"
            f"Target: {result.target_url}\n"
            f"Duration: {result.duration_seconds:.2f}s\n"
            f"Scan ID: {result.scan_id[:8]}"
        )

        panel = Panel(
            content,
            border_style="red",
            title="[bold red]SCAN FAILED[/bold red]",
            title_align="left",
        )
    else:
        content = (
            f"[bold green]NO ISSUES FOUND[/bold green]\n\n"
            f"Target: {result.target_url}\n"
            f"Duration: {result.duration_seconds:.2f}s\n"
            f"Scan ID: {result.scan_id[:8]}"
        )

        panel = Panel(
            content,
            border_style="green",
            title="[bold green]SCAN PASSED[/bold green]",
            title_align="left",
        )

    console.print()
    console.print(panel)


def show_error(message: str) -> None:
    """Display an error message without stack trace."""
    console.print(f"\n[bold red][ERROR][/bold red] {message}\n")


def show_vulnerabilities_detail(result: ScanResult) -> None:
    """Show detailed vulnerability information grouped by category."""
    if not result.vulnerabilities:
        return

    # Build category mapping from attack results
    attack_category_map = {}
    for attack in result.attack_results:
        category = getattr(attack, "category", None)
        if category:
            cat_value = category.value if hasattr(category, "value") else str(category)
        else:
            cat_value = "security"
        attack_category_map[attack.attack_type] = cat_value

    # Group vulnerabilities by category
    security_vulns = []
    reliability_vulns = []
    cost_vulns = []

    for vuln in result.vulnerabilities:
        vuln_category = "security"
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

    severity_colors = {
        "CRITICAL": "red",
        "HIGH": "orange1",
        "MEDIUM": "yellow",
        "LOW": "blue",
    }

    # Security vulnerabilities
    if security_vulns:
        console.print(f"\n[bold red]Security Vulnerabilities ({len(security_vulns)})[/bold red]\n")
        for i, vuln in enumerate(security_vulns, 1):
            color = severity_colors.get(vuln.severity.value, "white")
            console.print(f"[bold]{i}. {vuln.name}[/bold]")
            console.print(f"   Severity: [{color}]{vuln.severity.value}[/{color}]")
            console.print(f"   {vuln.description}")
            console.print(f"   [cyan]→ {settings.CTA_TEXT}: {settings.CTA_URL}[/cyan]")
            console.print()

    # Reliability issues
    if reliability_vulns:
        console.print(f"\n[bold yellow]Reliability Issues ({len(reliability_vulns)})[/bold yellow]\n")
        for i, vuln in enumerate(reliability_vulns, 1):
            color = severity_colors.get(vuln.severity.value, "white")
            console.print(f"[bold]{i}. {vuln.name}[/bold]")
            console.print(f"   Severity: [{color}]{vuln.severity.value}[/{color}]")
            console.print(f"   {vuln.description}")
            console.print(f"   [cyan]→ {settings.CTA_TEXT}: {settings.CTA_URL}[/cyan]")
            console.print()

    # Cost issues
    if cost_vulns:
        console.print(f"\n[bold blue]Cost & Performance Issues ({len(cost_vulns)})[/bold blue]\n")
        for i, vuln in enumerate(cost_vulns, 1):
            color = severity_colors.get(vuln.severity.value, "white")
            console.print(f"[bold]{i}. {vuln.name}[/bold]")
            console.print(f"   Severity: [{color}]{vuln.severity.value}[/{color}]")
            console.print(f"   {vuln.description}")
            console.print(f"   [cyan]→ {settings.CTA_TEXT}: {settings.CTA_URL}[/cyan]")
            console.print()
