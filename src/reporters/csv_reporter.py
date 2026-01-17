"""
CSV Reporter Module
===================

Exports scan results to CSV format for spreadsheet analysis.

This module creates properly formatted CSV files with:
- Metadata header rows for context
- Consistent column ordering
- Properly escaped values
- UTF-8 encoding support

Classes
-------
CSVReporter
    Main reporter class for CSV export.

Example
-------
>>> from src.reporters import CSVReporter
>>> from src.core import ScanResult
>>>
>>> reporter = CSVReporter(output_path="results.csv")
>>> filepath = reporter.report(scan_result)
>>> print(f"Results saved to: {filepath}")

Output Format
-------------
The CSV file includes:
1. Metadata header rows (prefixed with #)
2. Empty separator row
3. Column headers
4. Data rows

Example output::

    # Scan Metadata
    # Resource Type:,security_group
    # Region:,us-east-1
    # Total Resources:,50
    # Unused Resources:,5
    # Scan Time:,2024-01-15T10:30:00

    Region,Security Group ID,Name,VPC ID,Description,Is Default,Tags
    us-east-1,sg-123,my-sg,vpc-456,My security group,False,env=dev

See Also
--------
CLIReporter : For terminal display.
JSONReporter : For programmatic access.
"""

from __future__ import annotations

import csv
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from src.core.base_scanner import ScanResult
from src.core.region_manager import MultiRegionScanResult

# Module logger
logger = logging.getLogger(__name__)


class CSVReporter:
    """
    Reporter for exporting scan results to CSV format.

    Creates well-formatted CSV files with metadata headers and
    properly escaped values for compatibility with spreadsheet
    applications.

    Parameters
    ----------
    output_path : str, optional
        Path for the output file. If not provided, generates a
        timestamped filename in the current directory.

    Attributes
    ----------
    output_path : str or None
        The configured output path.

    Examples
    --------
    Export to specific file:

    >>> reporter = CSVReporter(output_path="./reports/results.csv")
    >>> filepath = reporter.report(scan_result)

    Auto-generate filename:

    >>> reporter = CSVReporter()
    >>> filepath = reporter.report(scan_result)
    >>> print(filepath)  # e.g., 'unused_security_groups_20240115_103000.csv'

    Multi-region export:

    >>> reporter = CSVReporter(output_path="all_regions.csv")
    >>> filepath = reporter.report(multi_region_result)

    See Also
    --------
    ScanResult : Single region scan results.
    MultiRegionScanResult : Multi-region scan results.
    """

    # CSV column definitions for security groups
    COLUMNS = [
        "Region",
        "Security Group ID",
        "Name",
        "VPC ID",
        "Description",
        "Is Default",
        "Tags",
    ]

    def __init__(self, output_path: Optional[str] = None) -> None:
        """Initialize the CSV reporter with an optional output path."""
        self.output_path = output_path
        logger.debug(f"Initialized CSVReporter (output_path={output_path})")

    def _get_output_path(self, resource_type: str) -> Path:
        """
        Get the output file path.

        Parameters
        ----------
        resource_type : str
            Type of resource for filename generation.

        Returns
        -------
        Path
            Path object for the output file.
        """
        if self.output_path:
            return Path(self.output_path)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"unused_{resource_type}s_{timestamp}.csv"
        return Path(filename)

    def report(
        self,
        result: Union[ScanResult, MultiRegionScanResult],
    ) -> str:
        """
        Export scan results to CSV (auto-detects result type).

        Parameters
        ----------
        result : ScanResult or MultiRegionScanResult
            Scan results to export.

        Returns
        -------
        str
            Path to the created CSV file.

        Example
        -------
        >>> reporter = CSVReporter()
        >>> filepath = reporter.report(scan_result)
        >>> print(f"Saved to: {filepath}")
        """
        if isinstance(result, MultiRegionScanResult):
            return self.report_multi_region(result)
        return self.report_single_region(result)

    def report_single_region(self, result: ScanResult) -> str:
        """
        Export single region scan results to CSV.

        Parameters
        ----------
        result : ScanResult
            Scan results from a single region.

        Returns
        -------
        str
            Path to the created CSV file.

        Example
        -------
        >>> reporter = CSVReporter(output_path="us-east-1-results.csv")
        >>> filepath = reporter.report_single_region(result)
        """
        output_path = self._get_output_path(result.resource_type)

        logger.info(f"Exporting {result.unused_count} resources to {output_path}")

        with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)

            # Write metadata header
            self._write_metadata(
                writer,
                resource_type=result.resource_type,
                regions=[result.region],
                total_resources=result.total_count,
                unused_resources=result.unused_count,
                scan_time=result.scan_time,
            )

            # Write column headers
            writer.writerow(self.COLUMNS)

            # Write data rows
            for resource in result.unused_resources:
                writer.writerow(self._format_resource_row(resource, result.region))

        logger.info(f"CSV export complete: {output_path}")
        return str(output_path)

    def report_multi_region(self, result: MultiRegionScanResult) -> str:
        """
        Export multi-region scan results to CSV.

        Parameters
        ----------
        result : MultiRegionScanResult
            Aggregated results from multiple regions.

        Returns
        -------
        str
            Path to the created CSV file.

        Example
        -------
        >>> reporter = CSVReporter(output_path="all-regions.csv")
        >>> filepath = reporter.report_multi_region(result)
        """
        output_path = self._get_output_path(result.resource_type)

        logger.info(f"Exporting {result.total_unused} resources to {output_path}")

        with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)

            # Write metadata header
            self._write_metadata(
                writer,
                resource_type=result.resource_type,
                regions=result.regions_scanned,
                total_resources=result.total_resources,
                unused_resources=result.total_unused,
                scan_time=result.scan_time,
            )

            # Write column headers
            writer.writerow(self.COLUMNS)

            # Write data rows (sorted by region)
            all_unused = result.get_all_unused_resources()
            sorted_resources = sorted(all_unused, key=lambda x: x.get("region", ""))

            for resource in sorted_resources:
                region = resource.get("region", "")
                writer.writerow(self._format_resource_row(resource, region))

        logger.info(f"CSV export complete: {output_path}")
        return str(output_path)

    def _write_metadata(
        self,
        writer: csv.writer,
        resource_type: str,
        regions: List[str],
        total_resources: int,
        unused_resources: int,
        scan_time: datetime,
    ) -> None:
        """
        Write metadata header rows to CSV.

        Parameters
        ----------
        writer : csv.writer
            CSV writer object.
        resource_type : str
            Type of resource scanned.
        regions : list of str
            Regions that were scanned.
        total_resources : int
            Total resources found.
        unused_resources : int
            Unused resources found.
        scan_time : datetime
            When the scan was performed.
        """
        writer.writerow(["# Scan Metadata"])
        writer.writerow(["# Resource Type:", resource_type])
        writer.writerow(["# Regions Scanned:", len(regions)])
        if len(regions) <= 5:
            writer.writerow(["# Region List:", ", ".join(regions)])
        writer.writerow(["# Total Resources:", total_resources])
        writer.writerow(["# Unused Resources:", unused_resources])
        writer.writerow(["# Scan Time:", scan_time.isoformat()])
        writer.writerow([])  # Empty row for separation

    def _format_resource_row(
        self,
        resource: Dict[str, Any],
        region: str,
    ) -> List[Any]:
        """
        Format a resource dictionary as a CSV row.

        Parameters
        ----------
        resource : dict
            Resource dictionary with keys like 'id', 'name', etc.
        region : str
            AWS region for this resource.

        Returns
        -------
        list
            Row data in column order.
        """
        return [
            region,
            resource.get("id", ""),
            resource.get("name", ""),
            resource.get("vpc_id", ""),
            resource.get("description", ""),
            resource.get("is_default", False),
            self._format_tags(resource.get("tags", {})),
        ]

    @staticmethod
    def _format_tags(tags: Dict[str, str]) -> str:
        """
        Format tags dictionary as a string for CSV.

        Parameters
        ----------
        tags : dict
            Dictionary of tag key-value pairs.

        Returns
        -------
        str
            Formatted string like "key1=value1; key2=value2".
        """
        if not tags:
            return ""
        return "; ".join(f"{k}={v}" for k, v in sorted(tags.items()))

    def __repr__(self) -> str:
        """Return string representation."""
        return f"CSVReporter(output_path={self.output_path!r})"
