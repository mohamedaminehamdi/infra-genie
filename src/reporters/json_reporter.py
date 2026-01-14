"""
JSON Reporter for exporting scan results to JSON files.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, Union

from ..core.base_scanner import ScanResult
from ..core.region_manager import MultiRegionScanResult


class JSONReporter:
    """
    Reporter for exporting scan results to JSON format.

    Provides structured JSON output suitable for programmatic consumption.
    """

    def __init__(self, output_path: Optional[str] = None, indent: int = 2):
        """
        Initialize the JSON reporter.

        Args:
            output_path: Path to output file. If None, generates timestamped filename.
            indent: JSON indentation level for pretty printing
        """
        self.output_path = output_path
        self.indent = indent

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
        filename = f"unused_{resource_type}s_{timestamp}.json"
        return Path(filename)

    def report_single_region(self, result: ScanResult) -> str:
        """
        Export single region scan results to JSON.

        Args:
            result: ScanResult from the scanner

        Returns:
            Path to the created JSON file
        """
        output_path = self._get_output_path(result.resource_type)

        data = {
            "metadata": {
                "resource_type": result.resource_type,
                "region": result.region,
                "total_resources": result.total_count,
                "unused_resources": result.unused_count,
                "scan_time": result.scan_time.isoformat(),
                "errors": result.errors,
            },
            "unused_resources": result.unused_resources,
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=self.indent, default=str)

        return str(output_path)

    def report_multi_region(self, result: MultiRegionScanResult) -> str:
        """
        Export multi-region scan results to JSON.

        Args:
            result: MultiRegionScanResult with aggregated data

        Returns:
            Path to the created JSON file
        """
        output_path = self._get_output_path(result.resource_type)

        data = {
            "metadata": {
                "resource_type": result.resource_type,
                "regions_scanned": result.regions_scanned,
                "total_resources": result.total_resources,
                "unused_resources": result.total_unused,
                "scan_time": result.scan_time.isoformat(),
                "errors": result.errors,
            },
            "summary_by_region": {
                region: {
                    "total": r.total_count,
                    "unused": r.unused_count,
                }
                for region, r in result.results_by_region.items()
            },
            "unused_resources": result.get_all_unused_resources(),
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=self.indent, default=str)

        return str(output_path)

    def report(self, result: Union[ScanResult, MultiRegionScanResult]) -> str:
        """
        Export scan results to JSON (auto-detects result type).

        Args:
            result: Either ScanResult or MultiRegionScanResult

        Returns:
            Path to the created JSON file
        """
        if isinstance(result, MultiRegionScanResult):
            return self.report_multi_region(result)
        else:
            return self.report_single_region(result)

    def to_string(self, result: Union[ScanResult, MultiRegionScanResult]) -> str:
        """
        Convert scan results to JSON string without writing to file.

        Args:
            result: Either ScanResult or MultiRegionScanResult

        Returns:
            JSON string representation
        """
        if isinstance(result, MultiRegionScanResult):
            data = {
                "metadata": {
                    "resource_type": result.resource_type,
                    "regions_scanned": result.regions_scanned,
                    "total_resources": result.total_resources,
                    "unused_resources": result.total_unused,
                    "scan_time": result.scan_time.isoformat(),
                    "errors": result.errors,
                },
                "summary_by_region": {
                    region: {
                        "total": r.total_count,
                        "unused": r.unused_count,
                    }
                    for region, r in result.results_by_region.items()
                },
                "unused_resources": result.get_all_unused_resources(),
            }
        else:
            data = {
                "metadata": {
                    "resource_type": result.resource_type,
                    "region": result.region,
                    "total_resources": result.total_count,
                    "unused_resources": result.unused_count,
                    "scan_time": result.scan_time.isoformat(),
                    "errors": result.errors,
                },
                "unused_resources": result.unused_resources,
            }

        return json.dumps(data, indent=self.indent, default=str)
