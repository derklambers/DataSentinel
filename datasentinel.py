
"""
DataSentinel
=============

Fast pre-commit scanner for:
- PII
- API keys
- Sensitive credentials
"""

from __future__ import annotations

import re
import subprocess

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional

import typer

from rich.console import Console
from rich.panel import Panel
from rich.table import Table


# =========================================================
# CLI Setup
# =========================================================

app = typer.Typer()
console = Console()


# =========================================================
# Data Models
# =========================================================

@dataclass
class Finding:
    """Represents a detected issue."""

    severity: str
    type: str
    file: str
    line: int
    value: str


@dataclass
class Detector:
    """Reusable detector definition."""

    name: str
    severity: str
    pattern: re.Pattern
    validator: Optional[Callable[[str], bool]] = None
    mask_value: bool = False


# =========================================================
# Validators
# =========================================================

def validate_iban(iban: str) -> bool:
    """Validate Dutch IBAN checksum."""

    iban = iban.replace(" ", "").upper()

    rearranged = iban[4:] + iban[:4]

    numeric = ""

    for ch in rearranged:

        if ch.isalpha():
            numeric += str(ord(ch) - 55)
        else:
            numeric += ch

    return int(numeric) % 97 == 1


def validate_bsn(bsn: str) -> bool:
    """Validate Dutch BSN using 11-test."""

    if len(bsn) == 8:
        bsn = "0" + bsn

    if len(bsn) != 9:
        return False

    total = 0

    for i in range(8):
        total += int(bsn[i]) * (9 - i)

    total -= int(bsn[-1])

    return total % 11 == 0


# =========================================================
# Utility Functions
# =========================================================

def mask_secret(value: str) -> str:
    """Mask sensitive values in output."""

    if len(value) <= 10:
        return "***"

    return value[:6] + "..."


def get_staged_files() -> List[str]:
    """Get staged Git files."""

    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only"],
        capture_output=True,
        text=True,
    )

    files = result.stdout.splitlines()

    return [
        f for f in files
        if Path(f).exists()
    ]


# =========================================================
# Detector Registry
# =========================================================

DETECTORS = [

    Detector(
        name="Email Address",
        severity="LOW",
        pattern=re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
        ),
    ),

    Detector(
        name="OpenAI API Key",
        severity="HIGH",
        pattern=re.compile(
            r"sk-[A-Za-z0-9]{20,}"
        ),
        mask_value=True,
    ),

    Detector(
        name="Dutch IBAN",
        severity="MEDIUM",
        pattern=re.compile(
            r"\bNL\d{2}[A-Z]{4}\d{10}\b"
        ),
        validator=validate_iban,
    ),

    Detector(
        name="BSN",
        severity="HIGH",
        pattern=re.compile(
            r"\b\d{8,9}\b"
        ),
        validator=validate_bsn,
    ),
]


# =========================================================
# Core Scanning Logic
# =========================================================

def run_detector(
    detector: Detector,
    filepath: str,
    line: str,
    line_no: int,
) -> List[Finding]:
    """Run detector on a line."""

    findings = []

    matches = detector.pattern.findall(line)

    for match in matches:

        if detector.validator:
            if not detector.validator(match):
                continue

        value = (
            mask_secret(match)
            if detector.mask_value
            else match
        )

        findings.append(
            Finding(
                severity=detector.severity,
                type=detector.name,
                file=filepath,
                line=line_no,
                value=value,
            )
        )

    return findings


def scan_file(filepath: str) -> List[Finding]:
    """Scan file contents."""

    findings = []

    try:

        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()

    except Exception:
        return findings

    for line_no, line in enumerate(lines, start=1):

        for detector in DETECTORS:

            findings.extend(
                run_detector(
                    detector=detector,
                    filepath=filepath,
                    line=line,
                    line_no=line_no,
                )
            )

    return findings


# =========================================================
# Reporting
# =========================================================

def render_report(findings: List[Finding]) -> None:
    """Render terminal report."""

    if not findings:

        console.print(
            Panel.fit(
                "[bold green]✓ No sensitive data detected[/bold green]"
            )
        )

        return

    table = Table(title="DataSentinel Scan Results")

    table.add_column("Severity")
    table.add_column("Type")
    table.add_column("File")
    table.add_column("Line")
    table.add_column("Value")

    for finding in findings:

        table.add_row(
            finding.severity,
            finding.type,
            finding.file,
            str(finding.line),
            finding.value,
        )

    console.print(table)


# =========================================================
# CLI Commands
# =========================================================

@app.command()
def scan():
    """Scan staged Git files."""

    files = get_staged_files()

    if not files:

        console.print(
            "[yellow]No staged files found.[/yellow]"
        )

        raise typer.Exit()

    all_findings = []

    for file in files:

        all_findings.extend(
            scan_file(file)
        )

    render_report(all_findings)

    high_findings = [
        f for f in all_findings
        if f.severity == "HIGH"
    ]

    if high_findings:

        console.print(
            "\n[bold red]"
            "Commit blocked due to HIGH severity findings."
            "[/bold red]"
        )

        raise typer.Exit(code=1)


# =========================================================
# Entry Point
# =========================================================

if __name__ == "__main__":
    app()
