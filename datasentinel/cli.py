
"""
CLI entrypoint for DataSentinel.
"""

from pathlib import Path
import typer

from .scanner import get_staged_files, scan_file
from .reporting import render_report

app = typer.Typer()


@app.command()
def scan():
    """
    Scan staged Git files.
    """

    files = get_staged_files()

    if not files:
        print("No staged files found.")
        raise typer.Exit()

    findings = []

    for file in files:
        findings.extend(
            scan_file(file)
        )

    render_report(findings)

    high_findings = [
        f for f in findings
        if f.severity == "HIGH"
    ]

    if high_findings:
        raise typer.Exit(code=1)


@app.command()
def install():
    """
    Install Git pre-commit hook.
    """

    hook_path = Path(".git/hooks/pre-commit")

    hook_content = """#!/bin/sh

datasentinel scan

if [ $? -ne 0 ]; then
    echo "Commit blocked by DataSentinel."
    exit 1
fi
"""

    hook_path.write_text(hook_content)

    hook_path.chmod(0o755)

    print("DataSentinel pre-commit hook installed.")
