"""
CLI Reporter for displaying scan results in the terminal.

Uses the 'rich' library for beautiful table formatting.
"""

from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from ..core.base_scanner import ScanResult
from ..core.region_manager import MultiRegionScanResult


class CLIReporter:
    """
    Reporter for displaying scan results in the CLI.

    Provides formatted tables and summary statistics using
    the rich library for enhanced visual output.
    """

    def __init__(self, console: Optional[Console] = None):
        """
        Initialize the CLI reporter.

        Args:
            console: Optional rich Console instance
        """
        self.console = console or Console()

    def report_single_region(self, result: ScanResult) -> None:
        """
        Report scan results for a single region.

        Args:
            result: ScanResult from the scanner
        """
        self._print_header(result.resource_type, [result.region])
        self._print_summary_single(result)

        if result.unused_resources:
            self._print_unused_resources_table(result.unused_resources, result.region)
        else:
            self.console.print(
                "\n[green]No unused resources found.[/green]"
            )

        if result.errors:
            self._print_errors({result.region: result.errors})

    def report_multi_region(self, result: MultiRegionScanResult) -> None:
        """
        Report scan results for multiple regions.

        Args:
            result: MultiRegionScanResult with aggregated data
        """
        self._print_header(result.resource_type, result.regions_scanned)
        self._print_summary_multi(result)

        unused_resources = result.get_all_unused_resources()
        if unused_resources:
            self._print_unused_resources_table_with_region(unused_resources)
        else:
            self.console.print(
                "\n[green]No unused resources found across all regions.[/green]"
            )

        if result.errors:
            self._print_errors(result.errors)

    def _print_header(self, resource_type: str, regions: List[str]) -> None:
        """Print the report header."""
        resource_name = resource_type.replace("_", " ").title()
        region_text = ", ".join(regions) if len(regions) <= 5 else f"{len(regions)} regions"

        header_text = Text()
        header_text.append(f"\n{resource_name} Scan Report\n", style="bold blue")
        header_text.append(f"Regions: {region_text}", style="dim")

        self.console.print(Panel(header_text, border_style="blue"))

    def _print_summary_single(self, result: ScanResult) -> None:
        """Print summary for single region scan."""
        summary = Table(show_header=False, box=None, padding=(0, 2))
        summary.add_column("Metric", style="cyan")
        summary.add_column("Value", style="white")

        summary.add_row("Region:", result.region)
        summary.add_row("Total Resources:", str(result.total_count))
        summary.add_row(
            "Unused Resources:",
            f"[{'red' if result.unused_count > 0 else 'green'}]{result.unused_count}[/]"
        )
        summary.add_row("Scan Time:", result.scan_time.strftime("%Y-%m-%d %H:%M:%S UTC"))

        self.console.print("\n")
        self.console.print(summary)

    def _print_summary_multi(self, result: MultiRegionScanResult) -> None:
        """Print summary for multi-region scan."""
        summary = Table(show_header=False, box=None, padding=(0, 2))
        summary.add_column("Metric", style="cyan")
        summary.add_column("Value", style="white")

        summary.add_row("Regions Scanned:", str(len(result.regions_scanned)))
        summary.add_row("Total Resources:", str(result.total_resources))
        summary.add_row(
            "Unused Resources:",
            f"[{'red' if result.total_unused > 0 else 'green'}]{result.total_unused}[/]"
        )
        summary.add_row("Scan Time:", result.scan_time.strftime("%Y-%m-%d %H:%M:%S UTC"))

        if result.errors:
            summary.add_row(
                "Errors:",
                f"[yellow]{len(result.errors)} region(s) had errors[/]"
            )

        self.console.print("\n")
        self.console.print(summary)

    def _print_unused_resources_table(
        self, resources: List[Dict[str, Any]], region: str
    ) -> None:
        """Print table of unused resources for single region."""
        table = Table(
            title=f"\nUnused Security Groups in {region}",
            title_style="bold",
            show_lines=False,
        )

        table.add_column("Security Group ID", style="cyan", no_wrap=True)
        table.add_column("Name", style="white")
        table.add_column("VPC ID", style="dim")
        table.add_column("Description", style="dim", max_width=50)

        for resource in resources:
            table.add_row(
                resource.get("id", "N/A"),
                resource.get("name", "N/A"),
                resource.get("vpc_id", "N/A"),
                self._truncate(resource.get("description", ""), 50),
            )

        self.console.print(table)

    def _print_unused_resources_table_with_region(
        self, resources: List[Dict[str, Any]]
    ) -> None:
        """Print table of unused resources with region column."""
        table = Table(
            title="\nUnused Security Groups",
            title_style="bold",
            show_lines=False,
        )

        table.add_column("Region", style="yellow", no_wrap=True)
        table.add_column("Security Group ID", style="cyan", no_wrap=True)
        table.add_column("Name", style="white")
        table.add_column("VPC ID", style="dim")
        table.add_column("Description", style="dim", max_width=40)

        # Sort by region for better readability
        sorted_resources = sorted(resources, key=lambda x: x.get("region", ""))

        for resource in sorted_resources:
            table.add_row(
                resource.get("region", "N/A"),
                resource.get("id", "N/A"),
                resource.get("name", "N/A"),
                resource.get("vpc_id", "N/A"),
                self._truncate(resource.get("description", ""), 40),
            )

        self.console.print(table)

    def _print_errors(self, errors: Dict[str, List[str]]) -> None:
        """Print any errors that occurred during scanning."""
        if not errors:
            return

        self.console.print("\n[yellow bold]Errors encountered:[/yellow bold]")

        for region, error_list in errors.items():
            self.console.print(f"\n[yellow]{region}:[/yellow]")
            for error in error_list:
                self.console.print(f"  [red]• {error}[/red]")

    def _truncate(self, text: str, max_length: int) -> str:
        """Truncate text to max length with ellipsis."""
        if len(text) <= max_length:
            return text
        return text[: max_length - 3] + "..."

    def create_progress(self) -> Progress:
        """
        Create a progress indicator for long-running scans.

        Returns:
            Progress instance for tracking scan progress
        """
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
        )

    def print_scanning_message(self, regions: List[str]) -> None:
        """Print a message about which regions are being scanned."""
        if len(regions) == 1:
            self.console.print(
                f"\n[bold]Scanning security groups in {regions[0]}...[/bold]"
            )
        else:
            region_preview = ", ".join(regions[:5])
            if len(regions) > 5:
                region_preview += f"... ({len(regions)} total)"
            self.console.print(
                f"\n[bold]Scanning security groups across {len(regions)} regions...[/bold]"
            )
            self.console.print(f"[dim]Regions: {region_preview}[/dim]")

    def print_completion_message(self, output_file: Optional[str] = None) -> None:
        """Print completion message."""
        self.console.print("\n[green bold]Scan complete![/green bold]")
        if output_file:
            self.console.print(f"[dim]Results saved to: {output_file}[/dim]")
