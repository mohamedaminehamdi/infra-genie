"""
CLI Reporter Module
===================

Provides rich terminal output for scan results using the Rich library.

This module creates visually appealing terminal displays with:
- Colored and formatted tables
- Progress indicators with spinners
- Summary panels with statistics
- Error highlighting and warnings

Classes
-------
CLIReporter
    Main reporter class for terminal output.

Example
-------
>>> from src.reporters import CLIReporter
>>> from src.core import ScanResult
>>>
>>> reporter = CLIReporter()
>>> reporter.report(scan_result)

Features
--------
- **Tables**: Formatted tables with alignment and coloring
- **Progress**: Spinner-based progress indicators for long operations
- **Panels**: Bordered panels for headers and summaries
- **Colors**: Status-based coloring (green for success, red for issues)

Notes
-----
The Rich library provides cross-platform terminal output that
degrades gracefully in terminals with limited capabilities.

See Also
--------
rich : Python library for rich text and formatting.
CSVReporter : For data export.
JSONReporter : For programmatic access.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Union

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from src.core.base_scanner import ScanResult
from src.core.region_manager import MultiRegionScanResult

# Module logger
logger = logging.getLogger(__name__)


class CLIReporter:
    """
    Reporter for displaying scan results in the terminal.

    Uses the Rich library for enhanced visual output including
    formatted tables, colored text, and progress indicators.

    Parameters
    ----------
    console : Console, optional
        Rich Console instance. If not provided, creates a new one.

    Attributes
    ----------
    console : Console
        The Rich Console used for output.

    Examples
    --------
    Basic usage:

    >>> reporter = CLIReporter()
    >>> reporter.report(scan_result)

    With custom console:

    >>> from rich.console import Console
    >>> console = Console(force_terminal=True)
    >>> reporter = CLIReporter(console=console)

    Displaying progress:

    >>> with reporter.create_progress() as progress:
    ...     task = progress.add_task("Scanning...", total=100)
    ...     for i in range(100):
    ...         progress.update(task, advance=1)

    See Also
    --------
    ScanResult : Single region scan results.
    MultiRegionScanResult : Multi-region scan results.
    """

    def __init__(self, console: Optional[Console] = None) -> None:
        """Initialize the CLI reporter with a Rich Console."""
        self.console = console or Console()
        logger.debug("Initialized CLIReporter")

    def report(self, result: Union[ScanResult, MultiRegionScanResult]) -> None:
        """
        Report scan results (auto-detects single vs multi-region).

        Parameters
        ----------
        result : ScanResult or MultiRegionScanResult
            The scan results to display.

        Example
        -------
        >>> reporter = CLIReporter()
        >>> reporter.report(scan_result)  # Works for both types
        """
        if isinstance(result, MultiRegionScanResult):
            self.report_multi_region(result)
        else:
            self.report_single_region(result)

    def report_single_region(self, result: ScanResult) -> None:
        """
        Report scan results for a single region.

        Parameters
        ----------
        result : ScanResult
            Scan results from a single region.

        Example
        -------
        >>> reporter = CLIReporter()
        >>> reporter.report_single_region(result)
        """
        self._print_header(result.resource_type, [result.region])
        self._print_summary_single(result)

        if result.unused_resources:
            self._print_unused_resources_table(result.unused_resources, result.region)
        else:
            self.console.print("\n[green]No unused resources found.[/green]")

        if result.errors:
            self._print_errors({result.region: result.errors})

    def report_multi_region(self, result: MultiRegionScanResult) -> None:
        """
        Report scan results for multiple regions.

        Parameters
        ----------
        result : MultiRegionScanResult
            Aggregated results from multiple regions.

        Example
        -------
        >>> reporter = CLIReporter()
        >>> reporter.report_multi_region(multi_result)
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

    # =========================================================================
    # Private Methods: Output Formatting
    # =========================================================================

    def _print_header(self, resource_type: str, regions: List[str]) -> None:
        """
        Print the report header panel.

        Parameters
        ----------
        resource_type : str
            Type of resource being reported.
        regions : list of str
            Regions included in the report.
        """
        resource_name = resource_type.replace("_", " ").title()
        region_text = (
            ", ".join(regions) if len(regions) <= 5
            else f"{len(regions)} regions"
        )

        header_text = Text()
        header_text.append(f"\n{resource_name} Scan Report\n", style="bold blue")
        header_text.append(f"Regions: {region_text}", style="dim")

        self.console.print(Panel(header_text, border_style="blue"))

    def _print_summary_single(self, result: ScanResult) -> None:
        """
        Print summary statistics for a single region scan.

        Parameters
        ----------
        result : ScanResult
            Single region scan results.
        """
        summary = Table(show_header=False, box=None, padding=(0, 2))
        summary.add_column("Metric", style="cyan")
        summary.add_column("Value", style="white")

        summary.add_row("Region:", result.region)
        summary.add_row("Total Resources:", str(result.total_count))

        # Color-code unused count based on value
        unused_style = "red" if result.unused_count > 0 else "green"
        summary.add_row(
            "Unused Resources:",
            f"[{unused_style}]{result.unused_count}[/]"
        )
        summary.add_row(
            "Scan Time:",
            result.scan_time.strftime("%Y-%m-%d %H:%M:%S UTC")
        )

        self.console.print("\n")
        self.console.print(summary)

    def _print_summary_multi(self, result: MultiRegionScanResult) -> None:
        """
        Print summary statistics for a multi-region scan.

        Parameters
        ----------
        result : MultiRegionScanResult
            Multi-region scan results.
        """
        summary = Table(show_header=False, box=None, padding=(0, 2))
        summary.add_column("Metric", style="cyan")
        summary.add_column("Value", style="white")

        summary.add_row("Regions Scanned:", str(len(result.regions_scanned)))
        summary.add_row("Total Resources:", str(result.total_resources))

        unused_style = "red" if result.total_unused > 0 else "green"
        summary.add_row(
            "Unused Resources:",
            f"[{unused_style}]{result.total_unused}[/]"
        )
        summary.add_row(
            "Scan Time:",
            result.scan_time.strftime("%Y-%m-%d %H:%M:%S UTC")
        )

        if result.errors:
            summary.add_row(
                "Errors:",
                f"[yellow]{len(result.errors)} region(s) had errors[/]"
            )

        self.console.print("\n")
        self.console.print(summary)

    def _print_unused_resources_table(
        self,
        resources: List[Dict[str, Any]],
        region: str,
    ) -> None:
        """
        Print table of unused resources for a single region.

        Parameters
        ----------
        resources : list of dict
            Unused resource dictionaries.
        region : str
            AWS region name.
        """
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
        self,
        resources: List[Dict[str, Any]],
    ) -> None:
        """
        Print table of unused resources with region column.

        Parameters
        ----------
        resources : list of dict
            Unused resources with 'region' key.
        """
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
        """
        Print errors encountered during scanning.

        Parameters
        ----------
        errors : dict
            Mapping of region name to list of error messages.
        """
        if not errors:
            return

        self.console.print("\n[yellow bold]Errors encountered:[/yellow bold]")

        for region, error_list in errors.items():
            self.console.print(f"\n[yellow]{region}:[/yellow]")
            for error in error_list:
                self.console.print(f"  [red]• {error}[/red]")

    @staticmethod
    def _truncate(text: str, max_length: int) -> str:
        """
        Truncate text to maximum length with ellipsis.

        Parameters
        ----------
        text : str
            Text to truncate.
        max_length : int
            Maximum length including ellipsis.

        Returns
        -------
        str
            Truncated text.
        """
        if len(text) <= max_length:
            return text
        return text[:max_length - 3] + "..."

    # =========================================================================
    # Public Methods: Progress and Messages
    # =========================================================================

    def create_progress(self) -> Progress:
        """
        Create a progress indicator for long-running operations.

        Returns
        -------
        Progress
            Rich Progress instance with spinner.

        Example
        -------
        >>> with reporter.create_progress() as progress:
        ...     task = progress.add_task("Scanning regions...", total=10)
        ...     for i in range(10):
        ...         # Do work
        ...         progress.update(task, advance=1)
        """
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
        )

    def print_scanning_message(self, regions: List[str]) -> None:
        """
        Print a message about regions being scanned.

        Parameters
        ----------
        regions : list of str
            Regions being scanned.

        Example
        -------
        >>> reporter.print_scanning_message(["us-east-1", "eu-west-1"])
        """
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
        """
        Print scan completion message.

        Parameters
        ----------
        output_file : str, optional
            Path to output file if results were saved.

        Example
        -------
        >>> reporter.print_completion_message("results.csv")
        """
        self.console.print("\n[green bold]Scan complete![/green bold]")
        if output_file:
            self.console.print(f"[dim]Results saved to: {output_file}[/dim]")

    def print_error(self, message: str) -> None:
        """
        Print an error message.

        Parameters
        ----------
        message : str
            Error message to display.

        Example
        -------
        >>> reporter.print_error("Failed to connect to AWS")
        """
        self.console.print(f"\n[red bold]Error:[/red bold] {message}")

    def print_warning(self, message: str) -> None:
        """
        Print a warning message.

        Parameters
        ----------
        message : str
            Warning message to display.

        Example
        -------
        >>> reporter.print_warning("Some regions were skipped")
        """
        self.console.print(f"\n[yellow bold]Warning:[/yellow bold] {message}")

    def __repr__(self) -> str:
        """Return string representation."""
        return "CLIReporter()"
