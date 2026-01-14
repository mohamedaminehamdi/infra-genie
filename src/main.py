"""
Infra-Genie CLI - AWS Resource Scanner

Main entry point for the command-line interface.
"""

import sys
from typing import Any, Dict, List, Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm
from rich.table import Table

from .cleaners.security_group_cleaner import (
    DeleteResult,
    DeleteStatus,
    DeleteSummary,
    SecurityGroupCleaner,
)
from .core.aws_client import AWSClient, AWSClientError
from .core.region_manager import RegionManager
from .reporters.cli_reporter import CLIReporter
from .reporters.csv_reporter import CSVReporter
from .reporters.json_reporter import JSONReporter
from .scanners.security_group_scanner import SecurityGroupScanner


console = Console()


def validate_regions(ctx, param, value: Optional[str]) -> Optional[List[str]]:
    """Validate and parse comma-separated region list."""
    if value is None:
        return None
    regions = [r.strip() for r in value.split(",") if r.strip()]
    if not regions:
        raise click.BadParameter("No valid regions specified")
    return regions


@click.group()
@click.version_option(version="0.1.0", prog_name="infra-genie")
def cli():
    """
    Infra-Genie: AWS Resource Scanner

    A modular tool for scanning AWS accounts to identify unused resources.
    Helps reduce cloud costs by finding orphaned security groups, unattached
    volumes, and other idle resources.
    """
    pass


@cli.group()
def scan():
    """Scan AWS resources for unused items."""
    pass


@scan.command("security-groups")
@click.option(
    "--region",
    "-r",
    default="us-east-1",
    help="AWS region to scan (default: us-east-1)",
)
@click.option(
    "--all-regions",
    is_flag=True,
    help="Scan all available AWS regions",
)
@click.option(
    "--regions",
    callback=validate_regions,
    help="Comma-separated list of regions to scan (e.g., us-east-1,us-west-2)",
)
@click.option(
    "--profile",
    "-p",
    default=None,
    help="AWS profile name from ~/.aws/credentials",
)
@click.option(
    "--output",
    "-o",
    default=None,
    help="Output file path (auto-detects format from extension)",
)
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["cli", "csv", "json"]),
    default="cli",
    help="Output format (default: cli)",
)
@click.option(
    "--include-default",
    is_flag=True,
    help="Include default VPC security groups in results",
)
@click.option(
    "--max-workers",
    default=10,
    type=int,
    help="Maximum parallel region scans (default: 10)",
)
def scan_security_groups(
    region: str,
    all_regions: bool,
    regions: Optional[List[str]],
    profile: Optional[str],
    output: Optional[str],
    output_format: str,
    include_default: bool,
    max_workers: int,
):
    """
    Scan for unused security groups.

    Identifies security groups that are not attached to any:
    - EC2 instances
    - Network interfaces (ENI)
    - RDS instances
    - Load balancers (ELB/ALB/NLB)
    - Other security group rules

    Examples:

        # Scan default region (us-east-1)
        infra-genie scan security-groups

        # Scan specific region
        infra-genie scan security-groups --region eu-west-1

        # Scan all regions
        infra-genie scan security-groups --all-regions

        # Scan multiple regions
        infra-genie scan security-groups --regions us-east-1,us-west-2,eu-west-1

        # Export to CSV
        infra-genie scan security-groups --all-regions --output results.csv

        # Export to JSON
        infra-genie scan security-groups --all-regions --format json -o results.json

        # Use specific AWS profile
        infra-genie scan security-groups --all-regions --profile production
    """
    cli_reporter = CLIReporter(console)
    exclude_default = not include_default

    try:
        # Validate credentials first
        try:
            test_client = AWSClient(region=region, profile=profile)
            test_client.validate_credentials()
        except AWSClientError as e:
            console.print(f"\n[red bold]Authentication Error:[/red bold] {str(e)}")
            sys.exit(1)

        # Determine which regions to scan
        if all_regions:
            region_manager = RegionManager(profile=profile, max_workers=max_workers)
            target_regions = region_manager.get_all_regions()
        elif regions:
            target_regions = regions
        else:
            target_regions = [region]

        cli_reporter.print_scanning_message(target_regions)

        # Perform scan
        if len(target_regions) == 1:
            # Single region scan
            result = _scan_single_region(
                target_regions[0], profile, exclude_default
            )
            _output_single_region_result(
                result, cli_reporter, output, output_format
            )
        else:
            # Multi-region scan
            result = _scan_multi_region(
                target_regions, profile, exclude_default, max_workers, cli_reporter
            )
            _output_multi_region_result(
                result, cli_reporter, output, output_format
            )

    except AWSClientError as e:
        console.print(f"\n[red bold]AWS Error:[/red bold] {str(e)}")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan cancelled by user.[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red bold]Error:[/red bold] {str(e)}")
        sys.exit(1)


def _scan_single_region(region: str, profile: Optional[str], exclude_default: bool):
    """Perform a single region scan."""
    client = AWSClient(region=region, profile=profile)
    scanner = SecurityGroupScanner(client, exclude_default=exclude_default)
    return scanner.scan()


def _scan_multi_region(
    regions: List[str],
    profile: Optional[str],
    exclude_default: bool,
    max_workers: int,
    cli_reporter: CLIReporter,
):
    """Perform a multi-region scan with progress indication."""
    region_manager = RegionManager(profile=profile, max_workers=max_workers)

    # Create a scanner class that includes our configuration
    class ConfiguredScanner(SecurityGroupScanner):
        def __init__(self, aws_client):
            super().__init__(aws_client, exclude_default=exclude_default)

    # Track progress
    completed_regions = set()

    def progress_callback(region: str, status: str):
        if status == "complete":
            completed_regions.add(region)
            console.print(
                f"  [dim]Completed: {region} ({len(completed_regions)}/{len(regions)})[/dim]"
            )
        elif status == "error":
            console.print(f"  [yellow]Error scanning: {region}[/yellow]")

    return region_manager.scan_regions(
        ConfiguredScanner,
        regions=regions,
        progress_callback=progress_callback,
    )


def _output_single_region_result(result, cli_reporter, output, output_format):
    """Handle output for single region scan result."""
    output_file = None

    if output_format == "cli" and not output:
        cli_reporter.report_single_region(result)
    elif output_format == "csv" or (output and output.endswith(".csv")):
        csv_reporter = CSVReporter(output_path=output)
        output_file = csv_reporter.report_single_region(result)
    elif output_format == "json" or (output and output.endswith(".json")):
        json_reporter = JSONReporter(output_path=output)
        output_file = json_reporter.report_single_region(result)
    else:
        # Default to CLI if format is cli but output is specified
        cli_reporter.report_single_region(result)
        if output:
            # Also save to file based on extension or default to CSV
            if output.endswith(".json"):
                json_reporter = JSONReporter(output_path=output)
                output_file = json_reporter.report_single_region(result)
            else:
                csv_reporter = CSVReporter(output_path=output)
                output_file = csv_reporter.report_single_region(result)

    cli_reporter.print_completion_message(output_file)


def _output_multi_region_result(result, cli_reporter, output, output_format):
    """Handle output for multi-region scan result."""
    output_file = None

    if output_format == "cli" and not output:
        cli_reporter.report_multi_region(result)
    elif output_format == "csv" or (output and output.endswith(".csv")):
        csv_reporter = CSVReporter(output_path=output)
        output_file = csv_reporter.report_multi_region(result)
        # Also show CLI summary
        cli_reporter.report_multi_region(result)
    elif output_format == "json" or (output and output.endswith(".json")):
        json_reporter = JSONReporter(output_path=output)
        output_file = json_reporter.report_multi_region(result)
        # Also show CLI summary
        cli_reporter.report_multi_region(result)
    else:
        cli_reporter.report_multi_region(result)
        if output:
            if output.endswith(".json"):
                json_reporter = JSONReporter(output_path=output)
                output_file = json_reporter.report_multi_region(result)
            else:
                csv_reporter = CSVReporter(output_path=output)
                output_file = csv_reporter.report_multi_region(result)

    cli_reporter.print_completion_message(output_file)


@cli.group()
def delete():
    """Delete unused AWS resources (use with caution)."""
    pass


@delete.command("security-groups")
@click.option(
    "--region",
    "-r",
    default="us-east-1",
    help="AWS region to delete from (default: us-east-1)",
)
@click.option(
    "--all-regions",
    is_flag=True,
    help="Delete from all available AWS regions",
)
@click.option(
    "--regions",
    callback=validate_regions,
    help="Comma-separated list of regions (e.g., us-east-1,us-west-2)",
)
@click.option(
    "--profile",
    "-p",
    default=None,
    help="AWS profile name from ~/.aws/credentials",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Preview what would be deleted without actually deleting",
)
@click.option(
    "--force",
    "-f",
    is_flag=True,
    default=False,
    help="Skip all confirmation prompts (dangerous!)",
)
@click.option(
    "--yes",
    "-y",
    is_flag=True,
    default=False,
    help="Automatically confirm batch deletion prompt",
)
@click.option(
    "--max-workers",
    default=10,
    type=int,
    help="Maximum parallel region scans (default: 10)",
)
def delete_security_groups(
    region: str,
    all_regions: bool,
    regions: Optional[List[str]],
    profile: Optional[str],
    dry_run: bool,
    force: bool,
    yes: bool,
    max_workers: int,
):
    """
    Delete unused security groups.

    First scans for unused security groups, then deletes them with confirmation.

    SAFETY FEATURES:
    - Dry-run mode (--dry-run): Preview without deleting
    - Confirmation prompt: Asks before deleting
    - Force mode (--force): Skip prompts (use with caution!)

    Examples:

        # Preview what would be deleted (safe)
        infra-genie delete security-groups --dry-run

        # Delete with confirmation prompt
        infra-genie delete security-groups --region us-east-1

        # Delete across all regions with confirmation
        infra-genie delete security-groups --all-regions

        # Skip confirmation (dangerous!)
        infra-genie delete security-groups --all-regions --force

        # Auto-confirm batch but still show summary
        infra-genie delete security-groups --all-regions --yes
    """
    try:
        # Validate credentials first
        try:
            test_client = AWSClient(region=region, profile=profile)
            test_client.validate_credentials()
        except AWSClientError as e:
            console.print(f"\n[red bold]Authentication Error:[/red bold] {str(e)}")
            sys.exit(1)

        # Determine which regions to process
        if all_regions:
            region_manager = RegionManager(profile=profile, max_workers=max_workers)
            target_regions = region_manager.get_all_regions()
        elif regions:
            target_regions = regions
        else:
            target_regions = [region]

        # Print mode indicator
        if dry_run:
            console.print(
                Panel(
                    "[yellow bold]DRY-RUN MODE[/yellow bold]\n"
                    "No security groups will actually be deleted.",
                    border_style="yellow",
                )
            )
        elif force:
            console.print(
                Panel(
                    "[red bold]FORCE MODE[/red bold]\n"
                    "Security groups will be deleted WITHOUT confirmation!",
                    border_style="red",
                )
            )

        # Step 1: Scan for unused security groups
        console.print(f"\n[bold]Step 1: Scanning for unused security groups...[/bold]")

        all_unused = []
        for target_region in target_regions:
            client = AWSClient(region=target_region, profile=profile)
            scanner = SecurityGroupScanner(client, exclude_default=True)
            result = scanner.scan()

            for sg in result.unused_resources:
                sg["region"] = target_region
                all_unused.append(sg)

            console.print(f"  [dim]{target_region}: {result.unused_count} unused[/dim]")

        if not all_unused:
            console.print("\n[green]No unused security groups found. Nothing to delete.[/green]")
            return

        # Step 2: Display what will be deleted
        console.print(f"\n[bold]Step 2: Found {len(all_unused)} unused security groups:[/bold]\n")
        _print_security_groups_table(all_unused)

        # Step 3: Confirm deletion
        if not dry_run and not force:
            console.print()
            if not yes:
                confirmed = Confirm.ask(
                    f"[yellow]Delete all {len(all_unused)} security groups?[/yellow]",
                    default=False,
                )
                if not confirmed:
                    console.print("\n[yellow]Deletion cancelled by user.[/yellow]")
                    return

        # Step 4: Perform deletion
        console.print(f"\n[bold]Step 3: {'Simulating' if dry_run else 'Deleting'} security groups...[/bold]\n")

        total_summary = DeleteSummary()

        # Group by region for efficient deletion
        by_region: Dict[str, List[Dict[str, Any]]] = {}
        for sg in all_unused:
            r = sg.get("region", region)
            if r not in by_region:
                by_region[r] = []
            by_region[r].append(sg)

        for target_region, sgs in by_region.items():
            client = AWSClient(region=target_region, profile=profile)
            cleaner = SecurityGroupCleaner(client)

            def progress_callback(result: DeleteResult):
                status_icon = {
                    DeleteStatus.SUCCESS: "[green]✓[/green]",
                    DeleteStatus.FAILED: "[red]✗[/red]",
                    DeleteStatus.SKIPPED: "[yellow]○[/yellow]",
                    DeleteStatus.DRY_RUN: "[blue]~[/blue]",
                }.get(result.status, "?")

                status_text = {
                    DeleteStatus.SUCCESS: "Deleted",
                    DeleteStatus.FAILED: f"Failed: {result.error_message}",
                    DeleteStatus.SKIPPED: "Skipped",
                    DeleteStatus.DRY_RUN: "Would delete",
                }.get(result.status, "Unknown")

                console.print(
                    f"  {status_icon} {result.sg_id} ({result.sg_name}) - {status_text}"
                )

            summary = cleaner.delete_batch(
                sgs,
                dry_run=dry_run,
                progress_callback=progress_callback,
            )

            # Aggregate results
            for result in summary.results:
                total_summary.add_result(result)

        total_summary.complete()

        # Step 5: Print summary
        _print_delete_summary(total_summary, dry_run)

    except AWSClientError as e:
        console.print(f"\n[red bold]AWS Error:[/red bold] {str(e)}")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Deletion cancelled by user.[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red bold]Error:[/red bold] {str(e)}")
        sys.exit(1)


def _print_security_groups_table(security_groups: List[Dict[str, Any]]) -> None:
    """Print a table of security groups."""
    table = Table(show_lines=False)
    table.add_column("#", style="dim", width=4)
    table.add_column("Region", style="yellow")
    table.add_column("Security Group ID", style="cyan")
    table.add_column("Name", style="white")
    table.add_column("Description", style="dim", max_width=40)

    for i, sg in enumerate(security_groups, 1):
        description = sg.get("description", "")
        if len(description) > 40:
            description = description[:37] + "..."

        table.add_row(
            str(i),
            sg.get("region", "N/A"),
            sg.get("id", "N/A"),
            sg.get("name", "N/A"),
            description,
        )

    console.print(table)


def _print_delete_summary(summary: DeleteSummary, dry_run: bool) -> None:
    """Print deletion summary."""
    console.print("\n" + "=" * 50)
    console.print("[bold]Summary[/bold]")
    console.print("=" * 50)

    if dry_run:
        console.print(f"  Would delete: [blue]{summary.dry_run}[/blue]")
    else:
        console.print(f"  Deleted:  [green]{summary.deleted}[/green]")
        console.print(f"  Failed:   [red]{summary.failed}[/red]")
        console.print(f"  Skipped:  [yellow]{summary.skipped}[/yellow]")

    console.print(f"  Total:    {summary.total}")

    if summary.failed > 0:
        console.print("\n[yellow]Some deletions failed. Common reasons:[/yellow]")
        console.print("  • Security group is still referenced by another resource")
        console.print("  • Security group is referenced by another security group's rules")
        console.print("  • Insufficient IAM permissions")

    console.print()


@cli.command("regions")
@click.option(
    "--profile",
    "-p",
    default=None,
    help="AWS profile name from ~/.aws/credentials",
)
def list_regions(profile: Optional[str]):
    """List all available AWS regions."""
    try:
        region_manager = RegionManager(profile=profile)
        regions = region_manager.get_all_regions()

        console.print(f"\n[bold]Available AWS Regions ({len(regions)} total):[/bold]\n")
        for region in regions:
            console.print(f"  • {region}")
        console.print()

    except AWSClientError as e:
        console.print(f"\n[red bold]Error:[/red bold] {str(e)}")
        sys.exit(1)


@cli.command("validate")
@click.option(
    "--profile",
    "-p",
    default=None,
    help="AWS profile name from ~/.aws/credentials",
)
@click.option(
    "--region",
    "-r",
    default="us-east-1",
    help="AWS region to use for validation",
)
def validate_credentials(profile: Optional[str], region: str):
    """Validate AWS credentials and show account info."""
    try:
        client = AWSClient(region=region, profile=profile)
        client.validate_credentials()
        account_id = client.get_account_id()

        console.print("\n[green bold]AWS credentials are valid![/green bold]")
        console.print(f"\n  Account ID: {account_id}")
        console.print(f"  Region: {region}")
        if profile:
            console.print(f"  Profile: {profile}")
        console.print()

    except AWSClientError as e:
        console.print(f"\n[red bold]Validation Failed:[/red bold] {str(e)}")
        sys.exit(1)


def main():
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()
