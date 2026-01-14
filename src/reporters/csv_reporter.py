"""
CSV Reporter for exporting scan results to CSV files.
"""

from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from ..core.base_scanner import ScanResult
from ..core.region_manager import MultiRegionScanResult


class CSVReporter:
    """
    Reporter for exporting scan results to CSV format.

    Handles proper escaping and formatting of CSV output.
    """

    def __init__(self, output_path: Optional[str] = None):
        """
        Initialize the CSV reporter.

        Args:
            output_path: Path to output file. If None, generates timestamped filename.
        """
        self.output_path = output_path

    def _get_output_path(self, resource_type: str) -> Path:
        """
        Get the output file path.

        Args:
            resource_type: Type of resource for filename generation

        Returns:
            Path object for the output file
        """
        if self.output_path:
            return Path(self.output_path)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"unused_{resource_type}s_{timestamp}.csv"
        return Path(filename)

    def report_single_region(self, result: ScanResult) -> str:
        """
        Export single region scan results to CSV.

        Args:
            result: ScanResult from the scanner

        Returns:
            Path to the created CSV file
        """
        output_path = self._get_output_path(result.resource_type)

        with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)

            # Write metadata as comments (some CSV readers support this)
            # Using a separate metadata row approach for better compatibility
            writer.writerow(["# Scan Metadata"])
            writer.writerow(["# Resource Type:", result.resource_type])
            writer.writerow(["# Region:", result.region])
            writer.writerow(["# Total Resources:", result.total_count])
            writer.writerow(["# Unused Resources:", result.unused_count])
            writer.writerow(["# Scan Time:", result.scan_time.isoformat()])
            writer.writerow([])  # Empty row for separation

            # Write header
            writer.writerow(
                [
                    "Region",
                    "Security Group ID",
                    "Name",
                    "VPC ID",
                    "Description",
                    "Is Default",
                    "Tags",
                ]
            )

            # Write data rows
            for resource in result.unused_resources:
                writer.writerow(
                    [
                        result.region,
                        resource.get("id", ""),
                        resource.get("name", ""),
                        resource.get("vpc_id", ""),
                        resource.get("description", ""),
                        resource.get("is_default", False),
                        self._format_tags(resource.get("tags", {})),
                    ]
                )

        return str(output_path)

    def report_multi_region(self, result: MultiRegionScanResult) -> str:
        """
        Export multi-region scan results to CSV.

        Args:
            result: MultiRegionScanResult with aggregated data

        Returns:
            Path to the created CSV file
        """
        output_path = self._get_output_path(result.resource_type)

        with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)

            # Write metadata
            writer.writerow(["# Scan Metadata"])
            writer.writerow(["# Resource Type:", result.resource_type])
            writer.writerow(["# Regions Scanned:", len(result.regions_scanned)])
            writer.writerow(["# Total Resources:", result.total_resources])
            writer.writerow(["# Unused Resources:", result.total_unused])
            writer.writerow(["# Scan Time:", result.scan_time.isoformat()])
            writer.writerow([])

            # Write header
            writer.writerow(
                [
                    "Region",
                    "Security Group ID",
                    "Name",
                    "VPC ID",
                    "Description",
                    "Is Default",
                    "Tags",
                ]
            )

            # Write data rows from all regions
            all_unused = result.get_all_unused_resources()
            # Sort by region for consistent output
            sorted_resources = sorted(all_unused, key=lambda x: x.get("region", ""))

            for resource in sorted_resources:
                writer.writerow(
                    [
                        resource.get("region", ""),
                        resource.get("id", ""),
                        resource.get("name", ""),
                        resource.get("vpc_id", ""),
                        resource.get("description", ""),
                        resource.get("is_default", False),
                        self._format_tags(resource.get("tags", {})),
                    ]
                )

        return str(output_path)

    def _format_tags(self, tags: Dict[str, str]) -> str:
        """
        Format tags dictionary as a string for CSV.

        Args:
            tags: Dictionary of tag key-value pairs

        Returns:
            Formatted string representation of tags
        """
        if not tags:
            return ""
        return "; ".join(f"{k}={v}" for k, v in sorted(tags.items()))

    def report(
        self, result: Union[ScanResult, MultiRegionScanResult]
    ) -> str:
        """
        Export scan results to CSV (auto-detects result type).

        Args:
            result: Either ScanResult or MultiRegionScanResult

        Returns:
            Path to the created CSV file
        """
        if isinstance(result, MultiRegionScanResult):
            return self.report_multi_region(result)
        else:
            return self.report_single_region(result)
