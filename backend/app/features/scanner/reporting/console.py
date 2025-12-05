# backend/app/features/scanner/reporting/console.py
"""Rich terminal UI for CLI output."""

from typing import List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..models import AttackResult, ScanResult

# Global console instance
console = Console()


def show_progress(message: str) -> None:
    """Show a progress message in the terminal."""
    # Color code based on message type
    if "[FAIL]" in message or "[ERROR]" in message or "[WARN]" in message:
        console.print(f"[red]{message}[/red]")
    elif "[PASS]" in message:
        console.print(f"[green]{message}[/green]")
    elif "[SKIP]" in message:
        console.print(f"[yellow]{message}[/yellow]")
    else:
        console.print(f"[cyan]{message}[/cyan]")


def show_attack_table(results: List[AttackResult]) -> None:
    """Display attack results in a formatted table."""
    table = Table(title="Attack Results", show_header=True, header_style="bold cyan")

    table.add_column("Attack Type", style="cyan", width=20)
    table.add_column("Status", justify="center", width=12)
    table.add_column("Vulnerabilities", justify="center", width=15)
    table.add_column("Latency", justify="right", width=10)

    for result in results:
        # Determine status style
        if result.status == "PASS":
            status_display = "[green]PASS[/green]"
        elif result.status == "FAIL":
            status_display = "[red]FAIL[/red]"
        else:
            status_display = "[yellow]ERROR[/yellow]"

        # Vulnerability count with color
        vuln_count = len(result.vulnerabilities)
        if vuln_count > 0:
            vuln_display = f"[red]{vuln_count}[/red]"
        else:
            vuln_display = "[green]0[/green]"

        table.add_row(
            result.attack_type,
            status_display,
            vuln_display,
            f"{result.latency_ms}ms",
        )

    console.print()
    console.print(table)


def show_summary(result: ScanResult) -> None:
    """Show the final scan summary panel."""
    vuln_count = len(result.vulnerabilities)

    # Count by severity
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for vuln in result.vulnerabilities:
        severity_counts[vuln.severity.value] += 1

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

        content = (
            f"[bold red]{vuln_count} VULNERABILITIES FOUND[/bold red]\n\n"
            f"{severity_str}\n\n"
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
            f"[bold green]NO VULNERABILITIES FOUND[/bold green]\n\n"
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
    """Show detailed vulnerability information."""
    if not result.vulnerabilities:
        return

    console.print("\n[bold]Vulnerability Details:[/bold]\n")

    for i, vuln in enumerate(result.vulnerabilities, 1):
        # Severity color
        severity_colors = {
            "CRITICAL": "red",
            "HIGH": "orange1",
            "MEDIUM": "yellow",
            "LOW": "blue",
        }
        color = severity_colors.get(vuln.severity.value, "white")

        console.print(f"[bold]{i}. {vuln.name}[/bold]")
        console.print(f"   Severity: [{color}]{vuln.severity.value}[/{color}]")
        console.print(f"   {vuln.description}")
        console.print()
