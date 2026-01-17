"""
Infra-Genie CLI
===============

Enterprise command-line interface for scanning and managing AWS resources.

This module provides the main entry point for the Infra-Genie CLI application,
implementing commands for:
- Scanning AWS resources for unused items
- Deleting unused resources with safety features
- Validating AWS credentials
- Listing available regions

Commands
--------
scan
    Scan AWS resources for unused items.
delete
    Delete unused AWS resources (with safety features).
regions
    List all available AWS regions.
validate
    Validate AWS credentials and show account info.

Example
-------
Command-line usage::

    # Scan for unused security groups
    $ infra-genie scan security-groups --all-regions

    # Delete with confirmation
    $ infra-genie delete security-groups --region us-east-1

    # Validate credentials
    $ infra-genie validate

See Also
--------
Click : Python composable command line interface toolkit.
Rich : Python library for rich text and formatting.
"""

from __future__ import annotations

import sys
from typing import Any, Dict, List, Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm
from rich.table import Table

from src.cleaners import DeleteResult, DeleteStatus, DeleteSummary, SecurityGroupCleaner
from src.core import AWSClient, AWSClientError, RegionManager
from src.reporters import CLIReporter, CSVReporter, JSONReporter
from src.scanners import EIPScanner, SecurityGroupScanner, SubnetScanner, VPCScanner

# Global console instance
console = Console()


# =============================================================================
# CLI Utilities
# =============================================================================


def validate_regions_callback(
    ctx: click.Context,
    param: click.Parameter,
    value: Optional[str],
) -> Optional[List[str]]:
    """
    Parse and validate comma-separated region list.

    Parameters
    ----------
    ctx : click.Context
        Click context.
    param : click.Parameter
        Click parameter.
    value : str or None
        Raw input value.

    Returns
    -------
    list of str or None
        Parsed region list or None.

    Raises
    ------
    click.BadParameter
        If no valid regions found.
    """
    if value is None:
        return None
    regions = [r.strip() for r in value.split(",") if r.strip()]
    if not regions:
        raise click.BadParameter("No valid regions specified")
    return regions


def handle_error(error: Exception, exit_code: int = 1) -> None:
    """
    Display error message and exit.

    Parameters
    ----------
    error : Exception
        The error to display.
    exit_code : int, default=1
        Exit code to use.
    """
    if isinstance(error, AWSClientError):
        console.print(f"\n[red bold]AWS Error:[/red bold] {error}")
    elif isinstance(error, KeyboardInterrupt):
        console.print("\n[yellow]Operation cancelled by user.[/yellow]")
        exit_code = 130
    else:
        console.print(f"\n[red bold]Error:[/red bold] {error}")
    sys.exit(exit_code)


# =============================================================================
# Main CLI Group
# =============================================================================


@click.group()
@click.version_option(version="0.1.0", prog_name="infra-genie")
def cli() -> None:
    """
    Infra-Genie: Enterprise AWS Resource Scanner & Cleaner

    A modular tool for scanning AWS accounts to identify unused resources
    and safely clean them up. Helps reduce cloud costs by finding orphaned
    security groups, unused VPCs, subnets, Elastic IPs, and other idle resources.

    \b
    QUICK START:
        infra-genie scan security-groups      Scan for unused security groups
        infra-genie scan vpcs                 Scan for unused VPCs
        infra-genie scan subnets              Scan for unused subnets
        infra-genie scan eips                 Scan for unused Elastic IPs
        infra-genie scan security-groups -A   Scan all regions
        infra-genie delete security-groups    Delete with confirmation

    \b
    DOCUMENTATION:
        https://infra-genie.readthedocs.io
    """
    pass


# =============================================================================
# Scan Commands
# =============================================================================


@cli.group()
def scan() -> None:
    """Scan AWS resources for unused items."""
    pass


@scan.command("security-groups")
@click.option(
    "--region", "-r",
    default="us-east-1",
    help="AWS region to scan (default: us-east-1)",
)
@click.option(
    "--all-regions", "-A",
    is_flag=True,
    help="Scan all available AWS regions",
)
@click.option(
    "--regions",
    callback=validate_regions_callback,
    help="Comma-separated list of regions (e.g., us-east-1,us-west-2)",
)
@click.option(
    "--profile", "-p",
    default=None,
    help="AWS profile name from ~/.aws/credentials",
)
@click.option(
    "--output", "-o",
    default=None,
    help="Output file path (auto-detects format from extension)",
)
@click.option(
    "--format", "-f",
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
) -> None:
    """
    Scan for unused security groups.

    Identifies security groups that are not attached to any:

    \b
    - EC2 instances
    - Network interfaces (ENI)
    - RDS instances
    - Load balancers (ELB/ALB/NLB)
    - Other security group rules

    \b
    EXAMPLES:
        # Scan default region (us-east-1)
        infra-genie scan security-groups

        # Scan specific region
        infra-genie scan security-groups -r eu-west-1

        # Scan all regions
        infra-genie scan security-groups --all-regions

        # Export to CSV
        infra-genie scan security-groups -A -o results.csv

        # Export to JSON
        infra-genie scan security-groups -A --format json -o results.json

        # Use specific AWS profile
        infra-genie scan security-groups -A -p production
    """
    cli_reporter = CLIReporter(console)
    exclude_default = not include_default

    try:
        # Validate credentials first
        _validate_credentials(region, profile)

        # Determine target regions
        target_regions = _get_target_regions(region, all_regions, regions, profile, max_workers)

        cli_reporter.print_scanning_message(target_regions)

        # Perform scan
        if len(target_regions) == 1:
            result = _scan_single_region(target_regions[0], profile, exclude_default)
            _output_single_region_result(result, cli_reporter, output, output_format)
        else:
            result = _scan_multi_region(
                target_regions, profile, exclude_default, max_workers, cli_reporter
            )
            _output_multi_region_result(result, cli_reporter, output, output_format)

    except Exception as e:
        handle_error(e)


@scan.command("vpcs")
@click.option(
    "--region", "-r",
    default="us-east-1",
    help="AWS region to scan (default: us-east-1)",
)
@click.option(
    "--all-regions", "-A",
    is_flag=True,
    help="Scan all available AWS regions",
)
@click.option(
    "--regions",
    callback=validate_regions_callback,
    help="Comma-separated list of regions (e.g., us-east-1,us-west-2)",
)
@click.option(
    "--profile", "-p",
    default=None,
    help="AWS profile name from ~/.aws/credentials",
)
@click.option(
    "--output", "-o",
    default=None,
    help="Output file path (auto-detects format from extension)",
)
@click.option(
    "--format", "-f",
    "output_format",
    type=click.Choice(["cli", "csv", "json"]),
    default="cli",
    help="Output format (default: cli)",
)
@click.option(
    "--include-default",
    is_flag=True,
    help="Include default VPC in results",
)
@click.option(
    "--max-workers",
    default=10,
    type=int,
    help="Maximum parallel region scans (default: 10)",
)
def scan_vpcs(
    region: str,
    all_regions: bool,
    regions: Optional[List[str]],
    profile: Optional[str],
    output: Optional[str],
    output_format: str,
    include_default: bool,
    max_workers: int,
) -> None:
    """
    Scan for unused VPCs.

    Identifies VPCs that have no active resources attached. A VPC is
    considered unused if it has none of the following:

    \b
    - EC2 instances
    - RDS instances
    - NAT Gateways
    - Load balancers (ELB/ALB/NLB)
    - Lambda functions (VPC-connected)
    - ElastiCache clusters
    - VPC Endpoints
    - Transit Gateway attachments
    - VPN connections
    - Active VPC peering connections
    - Network interfaces in use

    \b
    EXAMPLES:
        # Scan default region (us-east-1)
        infra-genie scan vpcs

        # Scan specific region
        infra-genie scan vpcs -r eu-west-1

        # Scan all regions
        infra-genie scan vpcs --all-regions

        # Include default VPC in results
        infra-genie scan vpcs --include-default

        # Export to CSV
        infra-genie scan vpcs -A -o results.csv

        # Export to JSON
        infra-genie scan vpcs -A --format json -o results.json

        # Use specific AWS profile
        infra-genie scan vpcs -A -p production
    """
    cli_reporter = CLIReporter(console)
    exclude_default = not include_default

    try:
        # Validate credentials first
        _validate_credentials(region, profile)

        # Determine target regions
        target_regions = _get_target_regions(region, all_regions, regions, profile, max_workers)

        cli_reporter.print_scanning_message(target_regions)

        # Perform scan
        if len(target_regions) == 1:
            result = _scan_vpcs_single_region(target_regions[0], profile, exclude_default)
            _output_single_region_result(result, cli_reporter, output, output_format)
        else:
            result = _scan_vpcs_multi_region(
                target_regions, profile, exclude_default, max_workers, cli_reporter
            )
            _output_multi_region_result(result, cli_reporter, output, output_format)

    except Exception as e:
        handle_error(e)


def _scan_vpcs_single_region(region: str, profile: Optional[str], exclude_default: bool):
    """Perform a single region VPC scan."""
    client = AWSClient(region=region, profile=profile)
    scanner = VPCScanner(client, exclude_default=exclude_default)
    return scanner.scan()


def _scan_vpcs_multi_region(
    regions: List[str],
    profile: Optional[str],
    exclude_default: bool,
    max_workers: int,
    cli_reporter: CLIReporter,
):
    """Perform a multi-region VPC scan with progress indication."""
    region_manager = RegionManager(profile=profile, max_workers=max_workers)

    # Create configured scanner class
    class ConfiguredVPCScanner(VPCScanner):
        def __init__(self, aws_client):
            super().__init__(aws_client, exclude_default=exclude_default)

    # Track progress
    completed_regions: set = set()

    def progress_callback(region: str, status: str) -> None:
        if status == "complete":
            completed_regions.add(region)
            console.print(
                f"  [dim]Completed: {region} ({len(completed_regions)}/{len(regions)})[/dim]"
            )
        elif status == "error":
            console.print(f"  [yellow]Error scanning: {region}[/yellow]")

    return region_manager.scan_regions(
        ConfiguredVPCScanner,
        regions=regions,
        progress_callback=progress_callback,
    )


@scan.command("subnets")
@click.option(
    "--region", "-r",
    default="us-east-1",
    help="AWS region to scan (default: us-east-1)",
)
@click.option(
    "--all-regions", "-A",
    is_flag=True,
    help="Scan all available AWS regions",
)
@click.option(
    "--regions",
    callback=validate_regions_callback,
    help="Comma-separated list of regions (e.g., us-east-1,us-west-2)",
)
@click.option(
    "--profile", "-p",
    default=None,
    help="AWS profile name from ~/.aws/credentials",
)
@click.option(
    "--output", "-o",
    default=None,
    help="Output file path (auto-detects format from extension)",
)
@click.option(
    "--format", "-f",
    "output_format",
    type=click.Choice(["cli", "csv", "json"]),
    default="cli",
    help="Output format (default: cli)",
)
@click.option(
    "--include-default",
    is_flag=True,
    help="Include default subnets in results",
)
@click.option(
    "--vpc-id",
    default=None,
    help="Filter subnets by specific VPC ID",
)
@click.option(
    "--max-workers",
    default=10,
    type=int,
    help="Maximum parallel region scans (default: 10)",
)
def scan_subnets(
    region: str,
    all_regions: bool,
    regions: Optional[List[str]],
    profile: Optional[str],
    output: Optional[str],
    output_format: str,
    include_default: bool,
    vpc_id: Optional[str],
    max_workers: int,
) -> None:
    """
    Scan for unused subnets.

    Identifies subnets that have no active resources deployed. A subnet is
    considered unused if it has none of the following:

    \b
    - EC2 instances
    - Network interfaces in use (ENIs)
    - NAT Gateways
    - Load balancers (ELB/ALB/NLB)
    - Lambda functions (VPC-connected)
    - RDS subnet group membership
    - ElastiCache subnet group membership
    - VPC Endpoints

    \b
    EXAMPLES:
        # Scan default region (us-east-1)
        infra-genie scan subnets

        # Scan specific region
        infra-genie scan subnets -r eu-west-1

        # Scan all regions
        infra-genie scan subnets --all-regions

        # Filter by specific VPC
        infra-genie scan subnets --vpc-id vpc-12345678

        # Include default subnets in results
        infra-genie scan subnets --include-default

        # Export to CSV
        infra-genie scan subnets -A -o results.csv

        # Export to JSON
        infra-genie scan subnets -A --format json -o results.json

        # Use specific AWS profile
        infra-genie scan subnets -A -p production
    """
    cli_reporter = CLIReporter(console)
    exclude_default = not include_default

    try:
        # Validate credentials first
        _validate_credentials(region, profile)

        # Determine target regions
        target_regions = _get_target_regions(region, all_regions, regions, profile, max_workers)

        cli_reporter.print_scanning_message(target_regions)

        # Perform scan
        if len(target_regions) == 1:
            result = _scan_subnets_single_region(
                target_regions[0], profile, exclude_default, vpc_id
            )
            _output_single_region_result(result, cli_reporter, output, output_format)
        else:
            result = _scan_subnets_multi_region(
                target_regions, profile, exclude_default, vpc_id, max_workers, cli_reporter
            )
            _output_multi_region_result(result, cli_reporter, output, output_format)

    except Exception as e:
        handle_error(e)


def _scan_subnets_single_region(
    region: str,
    profile: Optional[str],
    exclude_default: bool,
    vpc_id: Optional[str],
):
    """Perform a single region subnet scan."""
    client = AWSClient(region=region, profile=profile)
    scanner = SubnetScanner(client, exclude_default=exclude_default, vpc_id=vpc_id)
    return scanner.scan()


def _scan_subnets_multi_region(
    regions: List[str],
    profile: Optional[str],
    exclude_default: bool,
    vpc_id: Optional[str],
    max_workers: int,
    cli_reporter: CLIReporter,
):
    """Perform a multi-region subnet scan with progress indication."""
    region_manager = RegionManager(profile=profile, max_workers=max_workers)

    # Create configured scanner class
    class ConfiguredSubnetScanner(SubnetScanner):
        def __init__(self, aws_client):
            super().__init__(aws_client, exclude_default=exclude_default, vpc_id=vpc_id)

    # Track progress
    completed_regions: set = set()

    def progress_callback(region: str, status: str) -> None:
        if status == "complete":
            completed_regions.add(region)
            console.print(
                f"  [dim]Completed: {region} ({len(completed_regions)}/{len(regions)})[/dim]"
            )
        elif status == "error":
            console.print(f"  [yellow]Error scanning: {region}[/yellow]")

    return region_manager.scan_regions(
        ConfiguredSubnetScanner,
        regions=regions,
        progress_callback=progress_callback,
    )


@scan.command("eips")
@click.option(
    "--region", "-r",
    default="us-east-1",
    help="AWS region to scan (default: us-east-1)",
)
@click.option(
    "--all-regions", "-A",
    is_flag=True,
    help="Scan all available AWS regions",
)
@click.option(
    "--regions",
    callback=validate_regions_callback,
    help="Comma-separated list of regions (e.g., us-east-1,us-west-2)",
)
@click.option(
    "--profile", "-p",
    default=None,
    help="AWS profile name from ~/.aws/credentials",
)
@click.option(
    "--output", "-o",
    default=None,
    help="Output file path (auto-detects format from extension)",
)
@click.option(
    "--format", "-f",
    "output_format",
    type=click.Choice(["cli", "csv", "json"]),
    default="cli",
    help="Output format (default: cli)",
)
@click.option(
    "--max-workers",
    default=10,
    type=int,
    help="Maximum parallel region scans (default: 10)",
)
def scan_eips(
    region: str,
    all_regions: bool,
    regions: Optional[List[str]],
    profile: Optional[str],
    output: Optional[str],
    output_format: str,
    max_workers: int,
) -> None:
    """
    Scan for unused Elastic IPs.

    Identifies Elastic IP addresses that are allocated but not associated
    with any running instance or network interface. Unassociated EIPs
    incur hourly charges.

    \b
    COST IMPACT:
    AWS charges for Elastic IPs that are:
    - Allocated but not associated with a running instance
    - Associated with a stopped instance
    - Associated with an unattached network interface

    \b
    EXAMPLES:
        # Scan default region (us-east-1)
        infra-genie scan eips

        # Scan specific region
        infra-genie scan eips -r eu-west-1

        # Scan all regions
        infra-genie scan eips --all-regions

        # Export to CSV
        infra-genie scan eips -A -o results.csv

        # Export to JSON
        infra-genie scan eips -A --format json -o results.json

        # Use specific AWS profile
        infra-genie scan eips -A -p production
    """
    cli_reporter = CLIReporter(console)

    try:
        # Validate credentials first
        _validate_credentials(region, profile)

        # Determine target regions
        target_regions = _get_target_regions(region, all_regions, regions, profile, max_workers)

        cli_reporter.print_scanning_message(target_regions)

        # Perform scan
        if len(target_regions) == 1:
            result = _scan_eips_single_region(target_regions[0], profile)
            _output_single_region_result(result, cli_reporter, output, output_format)
        else:
            result = _scan_eips_multi_region(
                target_regions, profile, max_workers, cli_reporter
            )
            _output_multi_region_result(result, cli_reporter, output, output_format)

    except Exception as e:
        handle_error(e)


def _scan_eips_single_region(region: str, profile: Optional[str]):
    """Perform a single region EIP scan."""
    client = AWSClient(region=region, profile=profile)
    scanner = EIPScanner(client)
    return scanner.scan()


def _scan_eips_multi_region(
    regions: List[str],
    profile: Optional[str],
    max_workers: int,
    cli_reporter: CLIReporter,
):
    """Perform a multi-region EIP scan with progress indication."""
    region_manager = RegionManager(profile=profile, max_workers=max_workers)

    # Track progress
    completed_regions: set = set()

    def progress_callback(region: str, status: str) -> None:
        if status == "complete":
            completed_regions.add(region)
            console.print(
                f"  [dim]Completed: {region} ({len(completed_regions)}/{len(regions)})[/dim]"
            )
        elif status == "error":
            console.print(f"  [yellow]Error scanning: {region}[/yellow]")

    return region_manager.scan_regions(
        EIPScanner,
        regions=regions,
        progress_callback=progress_callback,
    )


def _validate_credentials(region: str, profile: Optional[str]) -> None:
    """Validate AWS credentials."""
    try:
        test_client = AWSClient(region=region, profile=profile)
        test_client.validate_credentials()
    except AWSClientError as e:
        console.print(f"\n[red bold]Authentication Error:[/red bold] {e}")
        sys.exit(1)


def _get_target_regions(
    region: str,
    all_regions: bool,
    regions: Optional[List[str]],
    profile: Optional[str],
    max_workers: int,
) -> List[str]:
    """Determine which regions to scan."""
    if all_regions:
        manager = RegionManager(profile=profile, max_workers=max_workers)
        return manager.get_all_regions()
    elif regions:
        return regions
    return [region]


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

    # Create configured scanner class
    class ConfiguredScanner(SecurityGroupScanner):
        def __init__(self, aws_client):
            super().__init__(aws_client, exclude_default=exclude_default)

    # Track progress
    completed_regions: set = set()

    def progress_callback(region: str, status: str) -> None:
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


def _output_single_region_result(result, cli_reporter, output, output_format) -> None:
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
        cli_reporter.report_single_region(result)
        if output:
            reporter = (
                JSONReporter(output_path=output) if output.endswith(".json")
                else CSVReporter(output_path=output)
            )
            output_file = reporter.report_single_region(result)

    cli_reporter.print_completion_message(output_file)


def _output_multi_region_result(result, cli_reporter, output, output_format) -> None:
    """Handle output for multi-region scan result."""
    output_file = None

    if output_format == "cli" and not output:
        cli_reporter.report_multi_region(result)
    elif output_format == "csv" or (output and output.endswith(".csv")):
        csv_reporter = CSVReporter(output_path=output)
        output_file = csv_reporter.report_multi_region(result)
        cli_reporter.report_multi_region(result)
    elif output_format == "json" or (output and output.endswith(".json")):
        json_reporter = JSONReporter(output_path=output)
        output_file = json_reporter.report_multi_region(result)
        cli_reporter.report_multi_region(result)
    else:
        cli_reporter.report_multi_region(result)
        if output:
            reporter = (
                JSONReporter(output_path=output) if output.endswith(".json")
                else CSVReporter(output_path=output)
            )
            output_file = reporter.report_multi_region(result)

    cli_reporter.print_completion_message(output_file)


# =============================================================================
# Delete Commands
# =============================================================================


@cli.group()
def delete() -> None:
    """Delete unused AWS resources (use with caution)."""
    pass


@delete.command("security-groups")
@click.option(
    "--region", "-r",
    default="us-east-1",
    help="AWS region to delete from (default: us-east-1)",
)
@click.option(
    "--all-regions", "-A",
    is_flag=True,
    help="Delete from all available AWS regions",
)
@click.option(
    "--regions",
    callback=validate_regions_callback,
    help="Comma-separated list of regions (e.g., us-east-1,us-west-2)",
)
@click.option(
    "--profile", "-p",
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
    "--force", "-f",
    is_flag=True,
    default=False,
    help="Skip all confirmation prompts (dangerous!)",
)
@click.option(
    "--yes", "-y",
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
) -> None:
    """
    Delete unused security groups.

    First scans for unused security groups, then deletes them with confirmation.

    \b
    SAFETY FEATURES:
    - Dry-run mode (--dry-run): Preview without deleting
    - Confirmation prompt: Asks before deleting
    - Force mode (--force): Skip prompts (use with caution!)

    \b
    EXAMPLES:
        # Preview what would be deleted (safe)
        infra-genie delete security-groups --dry-run

        # Delete with confirmation prompt
        infra-genie delete security-groups -r us-east-1

        # Delete across all regions with confirmation
        infra-genie delete security-groups --all-regions

        # Skip confirmation (dangerous!)
        infra-genie delete security-groups -A --force

        # Auto-confirm batch but still show summary
        infra-genie delete security-groups -A --yes
    """
    try:
        _validate_credentials(region, profile)
        target_regions = _get_target_regions(region, all_regions, regions, profile, max_workers)

        # Display mode indicators
        _print_mode_indicator(dry_run, force)

        # Step 1: Scan for unused security groups
        console.print("\n[bold]Step 1: Scanning for unused security groups...[/bold]")
        all_unused = _scan_for_unused_sgs(target_regions, profile)

        if not all_unused:
            console.print("\n[green]No unused security groups found. Nothing to delete.[/green]")
            return

        # Step 2: Display findings
        console.print(f"\n[bold]Step 2: Found {len(all_unused)} unused security groups:[/bold]\n")
        _print_security_groups_table(all_unused)

        # Step 3: Confirm deletion
        if not dry_run and not force:
            if not yes:
                console.print()
                confirmed = Confirm.ask(
                    f"[yellow]Delete all {len(all_unused)} security groups?[/yellow]",
                    default=False,
                )
                if not confirmed:
                    console.print("\n[yellow]Deletion cancelled by user.[/yellow]")
                    return

        # Step 4: Perform deletion
        action = "Simulating" if dry_run else "Deleting"
        console.print(f"\n[bold]Step 3: {action} security groups...[/bold]\n")

        summary = _delete_security_groups(all_unused, region, profile, dry_run)

        # Step 5: Print summary
        _print_delete_summary(summary, dry_run)

    except Exception as e:
        handle_error(e)


def _print_mode_indicator(dry_run: bool, force: bool) -> None:
    """Display mode indicator panel."""
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


def _scan_for_unused_sgs(
    target_regions: List[str],
    profile: Optional[str],
) -> List[Dict[str, Any]]:
    """Scan all target regions for unused security groups."""
    all_unused: List[Dict[str, Any]] = []

    for target_region in target_regions:
        client = AWSClient(region=target_region, profile=profile)
        scanner = SecurityGroupScanner(client, exclude_default=True)
        result = scanner.scan()

        for sg in result.unused_resources:
            sg["region"] = target_region
            all_unused.append(sg)

        console.print(f"  [dim]{target_region}: {result.unused_count} unused[/dim]")

    return all_unused


def _delete_security_groups(
    all_unused: List[Dict[str, Any]],
    default_region: str,
    profile: Optional[str],
    dry_run: bool,
) -> DeleteSummary:
    """Delete security groups and return summary."""
    total_summary = DeleteSummary()

    # Group by region
    by_region: Dict[str, List[Dict[str, Any]]] = {}
    for sg in all_unused:
        r = sg.get("region", default_region)
        if r not in by_region:
            by_region[r] = []
        by_region[r].append(sg)

    # Process each region
    for target_region, sgs in by_region.items():
        client = AWSClient(region=target_region, profile=profile)
        cleaner = SecurityGroupCleaner(client)

        def progress_callback(result: DeleteResult) -> None:
            icons = {
                DeleteStatus.SUCCESS: "[green]✓[/green]",
                DeleteStatus.FAILED: "[red]✗[/red]",
                DeleteStatus.SKIPPED: "[yellow]○[/yellow]",
                DeleteStatus.DRY_RUN: "[blue]~[/blue]",
            }
            texts = {
                DeleteStatus.SUCCESS: "Deleted",
                DeleteStatus.FAILED: f"Failed: {result.error_message}",
                DeleteStatus.SKIPPED: "Skipped",
                DeleteStatus.DRY_RUN: "Would delete",
            }
            icon = icons.get(result.status, "?")
            text = texts.get(result.status, "Unknown")
            console.print(f"  {icon} {result.sg_id} ({result.sg_name}) - {text}")

        summary = cleaner.delete_batch(sgs, dry_run=dry_run, progress_callback=progress_callback)

        for result in summary.results:
            total_summary.add_result(result)

    total_summary.complete()
    return total_summary


def _print_security_groups_table(security_groups: List[Dict[str, Any]]) -> None:
    """Print table of security groups."""
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


# =============================================================================
# Utility Commands
# =============================================================================


@cli.command("regions")
@click.option(
    "--profile", "-p",
    default=None,
    help="AWS profile name from ~/.aws/credentials",
)
def list_regions(profile: Optional[str]) -> None:
    """List all available AWS regions."""
    try:
        region_manager = RegionManager(profile=profile)
        regions = region_manager.get_all_regions()

        console.print(f"\n[bold]Available AWS Regions ({len(regions)} total):[/bold]\n")
        for region in regions:
            console.print(f"  • {region}")
        console.print()

    except AWSClientError as e:
        handle_error(e)


@cli.command("validate")
@click.option(
    "--profile", "-p",
    default=None,
    help="AWS profile name from ~/.aws/credentials",
)
@click.option(
    "--region", "-r",
    default="us-east-1",
    help="AWS region to use for validation",
)
def validate_credentials_cmd(profile: Optional[str], region: str) -> None:
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
        console.print(f"\n[red bold]Validation Failed:[/red bold] {e}")
        sys.exit(1)


# =============================================================================
# Entry Point
# =============================================================================


def main() -> None:
    """Main entry point for the CLI."""
    cli()


if __name__ == "__main__":
    main()
