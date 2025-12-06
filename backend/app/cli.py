# backend/app/cli.py
"""Typer CLI application for AI Security Scanner."""

import asyncio
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from backend.app.core import logs, settings
from backend.app.core.curl_parser import parse_curl, CurlParseError
from backend.app.features.scanner.reporting import (
    generate_html_report,
    open_report,
    show_attack_table,
    show_error,
    show_progress,
    show_summary,
)
from backend.app.features.scanner.services import ScannerService

app = typer.Typer(
    name="scanner",
    help="AI Security Scanner - Audit LLM/RAG applications for vulnerabilities",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()


@app.command()
def scan(
    target: Optional[str] = typer.Argument(
        None,
        help="Target LLM/RAG endpoint URL (e.g., https://example.com)",
    ),
    output: str = typer.Option(
        "report.html",
        "--output",
        "-o",
        help="Output file path for the HTML report",
    ),
    fast: bool = typer.Option(
        False,
        "--fast",
        "-f",
        help="Skip slow tests (RAG poisoning upload)",
    ),
    header: Optional[List[str]] = typer.Option(
        None,
        "--header",
        "-H",
        help="Custom headers (e.g., 'Authorization: Bearer KEY')",
    ),
    curl: Optional[str] = typer.Option(
        None,
        "--curl",
        help="Import target configuration from a cURL command",
    ),
    competitor: Optional[List[str]] = typer.Option(
        None,
        "--competitor",
        help="Competitor names to test against (e.g., 'Acme Corp')",
    ),
    concurrency: int = typer.Option(
        5,
        "--concurrency",
        "-c",
        help="Number of concurrent requests",
    ),
    llm_judge: bool = typer.Option(
        False,
        "--llm-judge",
        help="Use LLM-as-Judge for more accurate vulnerability detection (requires API key)",
    ),
    judge_provider: Optional[str] = typer.Option(
        None,
        "--judge-provider",
        help="LLM provider for judge: 'openai' or 'anthropic' (auto-detects if not set)",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Include raw AI responses in the report for analysis",
    ),
    pdf: bool = typer.Option(
        False,
        "--pdf",
        help="Generate PDF report in addition to HTML",
    ),
    no_open: bool = typer.Option(
        False,
        "--no-open",
        help="Don't automatically open the report in browser",
    ),
    sandbox: bool = typer.Option(
        False,
        "--sandbox",
        hidden=True,
        help="Internal sandbox mode (restricts to sandbox URL)",
    ),
) -> None:
    """
    Scan an LLM/RAG application for security vulnerabilities.

    Example usage:

        scanner scan https://example.com

        scanner scan https://example.com --fast --output audit.html

        scanner scan https://example.com -H "Authorization: Bearer sk-xxx"

        scanner scan --curl "curl https://api.example.com -H 'Auth: token'"

        scanner scan https://example.com --competitor "Acme" --competitor "ACME Corp"
    """
    try:
        # Handle cURL import
        if curl:
            try:
                curl_config = parse_curl(curl)
                target = curl_config.base_url
                # Merge cURL headers with explicit headers (explicit takes precedence)
                for key, value in curl_config.headers.items():
                    if key not in (header or []):
                        if header is None:
                            header = []
                        header.append(f"{key}: {value}")
                console.print(f"[dim]Imported from cURL: {curl_config.url}[/dim]")
            except CurlParseError as e:
                show_error(f"Failed to parse cURL command: {e}")
                raise typer.Exit(1)

        # Validate target
        if not target:
            show_error("Target URL is required. Provide it as argument or via --curl")
            raise typer.Exit(1)

        # Parse headers
        headers = {}
        if header:
            for h in header:
                if ":" in h:
                    key, value = h.split(":", 1)
                    headers[key.strip()] = value.strip()

        # Parse competitors
        competitors = list(competitor) if competitor else None

        # Show banner
        console.print()
        console.print(
            f"[bold cyan]AI Security Scanner[/bold cyan] v{settings.APP_VERSION}"
        )
        console.print()
        console.print(f"Target: [cyan]{target}[/cyan]")
        console.print(f"Output: [dim]{output}[/dim]")
        if fast:
            console.print("[yellow]Fast mode: Skipping RAG upload tests[/yellow]")
        if competitors:
            console.print(f"[dim]Competitors: {', '.join(competitors)}[/dim]")
        if llm_judge:
            console.print("[cyan]LLM Judge: Enabled (uses API credits)[/cyan]")
        console.print()

        # Sandbox mode check (for internal use)
        if sandbox and settings.SANDBOX_URL not in target:
            show_error(f"Sandbox mode only allows: {settings.SANDBOX_URL}")
            raise typer.Exit(1)

        # Run the scan
        result = asyncio.run(_run_scan(
            target, fast, headers, competitors, llm_judge, judge_provider
        ))

        # Display results
        console.print()
        show_attack_table(result.attack_results)
        show_summary(result)

        # Generate report
        report_path = generate_html_report(result, output, verbose=verbose)
        console.print()
        console.print(f"[dim]Report saved to: {report_path}[/dim]")

        # Generate PDF if requested
        if pdf:
            from backend.app.features.scanner.reporting.pdf import generate_pdf_report
            pdf_output = output.replace(".html", ".pdf") if output.endswith(".html") else f"{output}.pdf"
            pdf_path = generate_pdf_report(result, pdf_output, verbose=verbose)
            console.print(f"[dim]PDF saved to: {pdf_path}[/dim]")

        # Open report in browser
        if not no_open:
            open_report(report_path)

        # Exit with error code if vulnerabilities found
        if result.vulnerabilities:
            raise typer.Exit(1)

    except typer.Exit:
        raise
    except Exception as e:
        show_error(str(e))
        raise typer.Exit(1)


async def _run_scan(
    target: str,
    fast: bool,
    headers: dict,
    competitors: Optional[List[str]] = None,
    use_llm_judge: bool = False,
    judge_provider: Optional[str] = None,
):
    """Run the scan asynchronously with progress display."""
    scanner = ScannerService(
        competitors=competitors,
        use_llm_judge=use_llm_judge,
        judge_provider=judge_provider,
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Initializing scan...", total=None)

        def on_progress(message: str) -> None:
            # Update spinner description
            progress.update(task, description=message)
            # Also print the message
            show_progress(message)

        result = await scanner.scan(
            target_url=target,
            fast=fast,
            headers=headers,
            on_progress=on_progress,
        )

    return result


@app.command()
def version() -> None:
    """Show version information."""
    console.print(f"AI Security Scanner v{settings.APP_VERSION}")


@app.command()
def info() -> None:
    """Show configuration information."""
    console.print()
    console.print("[bold]Configuration[/bold]")
    console.print()
    console.print(f"  App Name:      {settings.APP_NAME}")
    console.print(f"  Version:       {settings.APP_VERSION}")
    console.print(f"  Environment:   {settings.ENVIRONMENT}")
    console.print(f"  Sandbox URL:   {settings.SANDBOX_URL}")
    console.print(f"  Timeout:       {settings.REQUEST_TIMEOUT}s")
    console.print()


if __name__ == "__main__":
    app()
