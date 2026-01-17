"""
JSON Reporter Module
====================

Exports scan results to JSON format for programmatic access and API integration.

This module creates structured JSON output with:
- Complete metadata section
- Region-level summaries (for multi-region scans)
- Full resource details
- Error information

Classes
-------
JSONReporter
    Main reporter class for JSON export.

Example
-------
>>> from src.reporters import JSONReporter
>>> from src.core import ScanResult
>>>
>>> reporter = JSONReporter(output_path="results.json")
>>> filepath = reporter.report(scan_result)
>>>
>>> # Or get as string for API responses
>>> json_str = reporter.to_string(scan_result)

Output Structure
----------------
Single region::

    {
      "metadata": {
        "resource_type": "security_group",
        "region": "us-east-1",
        "total_resources": 50,
        "unused_resources": 5,
        "scan_time": "2024-01-15T10:30:00",
        "errors": []
      },
      "unused_resources": [...]
    }

Multi-region::

    {
      "metadata": {...},
      "summary_by_region": {
        "us-east-1": {"total": 30, "unused": 3},
        "eu-west-1": {"total": 20, "unused": 2}
      },
      "unused_resources": [...]
    }

See Also
--------
CLIReporter : For terminal display.
CSVReporter : For spreadsheet export.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Union

from src.core.base_scanner import ScanResult
from src.core.region_manager import MultiRegionScanResult

# Module logger
logger = logging.getLogger(__name__)


class JSONReporter:
    """
    Reporter for exporting scan results to JSON format.

    Creates structured JSON output suitable for programmatic
    consumption, API responses, and data pipelines.

    Parameters
    ----------
    output_path : str, optional
        Path for the output file. If not provided, generates a
        timestamped filename in the current directory.
    indent : int, default=2
        JSON indentation level for pretty printing.
        Set to None for compact output.

    Attributes
    ----------
    output_path : str or None
        The configured output path.
    indent : int or None
        JSON indentation level.

    Examples
    --------
    Export to file:

    >>> reporter = JSONReporter(output_path="results.json")
    >>> filepath = reporter.report(scan_result)

    Get as string for API response:

    >>> reporter = JSONReporter()
    >>> json_str = reporter.to_string(scan_result)
    >>> return JsonResponse(json.loads(json_str))

    Compact output (no indentation):

    >>> reporter = JSONReporter(indent=None)
    >>> json_str = reporter.to_string(scan_result)

    See Also
    --------
    ScanResult : Single region scan results.
    MultiRegionScanResult : Multi-region scan results.
    """

    def __init__(
        self,
        output_path: Optional[str] = None,
        indent: Optional[int] = 2,
    ) -> None:
        """Initialize the JSON reporter with optional output path and indentation."""
        self.output_path = output_path
        self.indent = indent
        logger.debug(f"Initialized JSONReporter (output_path={output_path})")

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
        filename = f"unused_{resource_type}s_{timestamp}.json"
        return Path(filename)

    def report(
        self,
        result: Union[ScanResult, MultiRegionScanResult],
    ) -> str:
        """
        Export scan results to JSON file (auto-detects result type).

        Parameters
        ----------
        result : ScanResult or MultiRegionScanResult
            Scan results to export.

        Returns
        -------
        str
            Path to the created JSON file.

        Example
        -------
        >>> reporter = JSONReporter()
        >>> filepath = reporter.report(scan_result)
        >>> print(f"Saved to: {filepath}")
        """
        if isinstance(result, MultiRegionScanResult):
            return self.report_multi_region(result)
        return self.report_single_region(result)

    def report_single_region(self, result: ScanResult) -> str:
        """
        Export single region scan results to JSON file.

        Parameters
        ----------
        result : ScanResult
            Scan results from a single region.

        Returns
        -------
        str
            Path to the created JSON file.

        Example
        -------
        >>> reporter = JSONReporter(output_path="us-east-1.json")
        >>> filepath = reporter.report_single_region(result)
        """
        output_path = self._get_output_path(result.resource_type)

        logger.info(f"Exporting {result.unused_count} resources to {output_path}")

        data = self._build_single_region_data(result)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=self.indent, default=str)

        logger.info(f"JSON export complete: {output_path}")
        return str(output_path)

    def report_multi_region(self, result: MultiRegionScanResult) -> str:
        """
        Export multi-region scan results to JSON file.

        Parameters
        ----------
        result : MultiRegionScanResult
            Aggregated results from multiple regions.

        Returns
        -------
        str
            Path to the created JSON file.

        Example
        -------
        >>> reporter = JSONReporter(output_path="all-regions.json")
        >>> filepath = reporter.report_multi_region(result)
        """
        output_path = self._get_output_path(result.resource_type)

        logger.info(f"Exporting {result.total_unused} resources to {output_path}")

        data = self._build_multi_region_data(result)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=self.indent, default=str)

        logger.info(f"JSON export complete: {output_path}")
        return str(output_path)

    def to_string(
        self,
        result: Union[ScanResult, MultiRegionScanResult],
    ) -> str:
        """
        Convert scan results to JSON string without writing to file.

        Parameters
        ----------
        result : ScanResult or MultiRegionScanResult
            Scan results to convert.

        Returns
        -------
        str
            JSON string representation.

        Example
        -------
        >>> reporter = JSONReporter()
        >>> json_str = reporter.to_string(scan_result)
        >>> data = json.loads(json_str)
        """
        if isinstance(result, MultiRegionScanResult):
            data = self._build_multi_region_data(result)
        else:
            data = self._build_single_region_data(result)

        return json.dumps(data, indent=self.indent, default=str)

    def to_dict(
        self,
        result: Union[ScanResult, MultiRegionScanResult],
    ) -> Dict[str, Any]:
        """
        Convert scan results to a Python dictionary.

        Parameters
        ----------
        result : ScanResult or MultiRegionScanResult
            Scan results to convert.

        Returns
        -------
        dict
            Dictionary representation of the results.

        Example
        -------
        >>> reporter = JSONReporter()
        >>> data = reporter.to_dict(scan_result)
        >>> print(data["metadata"]["total_resources"])
        """
        if isinstance(result, MultiRegionScanResult):
            return self._build_multi_region_data(result)
        return self._build_single_region_data(result)

    # =========================================================================
    # Private Methods: Data Building
    # =========================================================================

    def _build_single_region_data(self, result: ScanResult) -> Dict[str, Any]:
        """
        Build data dictionary for single region results.

        Parameters
        ----------
        result : ScanResult
            Single region scan results.

        Returns
        -------
        dict
            Structured data dictionary.
        """
        return {
            "metadata": {
                "resource_type": result.resource_type,
                "region": result.region,
                "total_resources": result.total_count,
                "unused_resources": result.unused_count,
                "usage_percentage": round(result.usage_percentage, 2),
                "scan_time": result.scan_time.isoformat(),
                "errors": result.errors,
            },
            "unused_resources": result.unused_resources,
        }

    def _build_multi_region_data(
        self,
        result: MultiRegionScanResult,
    ) -> Dict[str, Any]:
        """
        Build data dictionary for multi-region results.

        Parameters
        ----------
        result : MultiRegionScanResult
            Multi-region scan results.

        Returns
        -------
        dict
            Structured data dictionary.
        """
        return {
            "metadata": {
                "resource_type": result.resource_type,
                "regions_scanned": result.regions_scanned,
                "total_regions": len(result.regions_scanned),
                "successful_regions": len(result.successful_regions),
                "failed_regions": len(result.failed_regions),
                "total_resources": result.total_resources,
                "unused_resources": result.total_unused,
                "usage_percentage": round(result.usage_percentage, 2),
                "scan_time": result.scan_time.isoformat(),
                "errors": result.errors,
            },
            "summary_by_region": {
                region: {
                    "total": r.total_count,
                    "unused": r.unused_count,
                    "used": r.total_count - r.unused_count,
                }
                for region, r in result.results_by_region.items()
            },
            "unused_resources": result.get_all_unused_resources(),
        }

    def __repr__(self) -> str:
        """Return string representation."""
        return f"JSONReporter(output_path={self.output_path!r}, indent={self.indent})"
