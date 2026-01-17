"""
Report Generators
=================

This module provides output formatters for scan and cleanup results.

Each reporter transforms scan results into a specific format suitable
for different use cases (terminal display, data export, API responses).

Available Reporters
-------------------
CLIReporter
    Rich terminal output with formatted tables and progress indicators.
CSVReporter
    CSV export for spreadsheet analysis and data processing.
JSONReporter
    JSON export for API integration and programmatic access.

Example
-------
>>> from src.reporters import CLIReporter, CSVReporter, JSONReporter
>>> from src.core import ScanResult
>>>
>>> # Display in terminal
>>> cli = CLIReporter()
>>> cli.report(scan_result)
>>>
>>> # Export to CSV
>>> csv_reporter = CSVReporter(output_dir="./reports")
>>> filepath = csv_reporter.report(scan_result)
>>>
>>> # Get as JSON
>>> json_reporter = JSONReporter()
>>> json_str = json_reporter.to_string(scan_result)

Output Formats
--------------
**CLI (Terminal)**
    - Colored output with status indicators
    - Formatted tables for resource lists
    - Summary statistics
    - Error highlighting

**CSV**
    - Spreadsheet-compatible format
    - One row per unused resource
    - Includes all resource metadata
    - Optional metadata header

**JSON**
    - Machine-readable format
    - Complete scan data structure
    - Suitable for API responses
    - Can output to file or string

See Also
--------
src.core.base_scanner.ScanResult : Input data structure.
src.core.region_manager.MultiRegionScanResult : Multi-region input.
"""

from src.reporters.cli_reporter import CLIReporter
from src.reporters.csv_reporter import CSVReporter
from src.reporters.json_reporter import JSONReporter

__all__ = [
    "CLIReporter",
    "CSVReporter",
    "JSONReporter",
]
