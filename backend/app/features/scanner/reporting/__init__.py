# backend/app/features/scanner/reporting/__init__.py
"""Reporting modules for scan results."""

from .html import generate_html_report, open_report
from .console import (
    console,
    show_progress,
    show_attack_table,
    show_failures_summary,
    show_summary,
    show_error,
)

__all__ = [
    "generate_html_report",
    "open_report",
    "console",
    "show_progress",
    "show_attack_table",
    "show_failures_summary",
    "show_summary",
    "show_error",
]
