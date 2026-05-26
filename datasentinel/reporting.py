
"""
Terminal reporting utilities.
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def render_report(findings):
    """
    Render terminal report.
    """

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
