
"""
Core scanning engine.
"""

import subprocess
from pathlib import Path

from .detectors import DETECTORS
from .models import Finding


def mask_secret(value: str) -> str:
    """
    Hide sensitive values in terminal output.
    """

    if len(value) <= 10:
        return "***"

    return value[:6] + "..."


def get_staged_files():
    """
    Return staged git files.
    """

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


def run_detector(detector, filepath, line, line_no):
    """
    Run detector against a single line.
    """

    findings = []

    if "datasentinel: ignore" in line:
        return findings

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


def scan_file(filepath):
    """
    Scan file line-by-line.
    """

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
                    detector,
                    filepath,
                    line,
                    line_no,
                )
            )

    return findings
