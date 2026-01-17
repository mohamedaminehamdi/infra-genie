"""
Infra-Genie: Enterprise AWS Resource Scanner & Cleaner
======================================================

A modular, enterprise-grade tool for scanning AWS accounts to identify
and clean up unused resources, helping teams reduce cloud costs.

Modules
-------
core
    Core infrastructure components (AWS client, base scanner, region manager)
scanners
    Resource-specific scanner implementations
cleaners
    Resource-specific cleaner implementations
reporters
    Output formatters (CLI, CSV, JSON)

Example
-------
>>> from src.core import AWSClient, RegionManager
>>> from src.scanners import SecurityGroupScanner
>>>
>>> client = AWSClient(region="us-east-1")
>>> scanner = SecurityGroupScanner(client)
>>> result = scanner.scan()
>>> print(f"Found {result.unused_count} unused security groups")

Notes
-----
Requires AWS credentials configured via:
- Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
- AWS credentials file (~/.aws/credentials)
- IAM role (when running on AWS infrastructure)

See Also
--------
boto3 : AWS SDK for Python
"""

__version__ = "0.1.0"
__author__ = "Infra-Genie Team"
__license__ = "MIT"

# Public API
from src.core.aws_client import AWSClient, AWSClientError
from src.core.base_scanner import BaseScanner, ScanResult
from src.core.region_manager import MultiRegionScanResult, RegionManager

__all__ = [
    # Version info
    "__version__",
    "__author__",
    "__license__",
    # Core classes
    "AWSClient",
    "AWSClientError",
    "BaseScanner",
    "ScanResult",
    "RegionManager",
    "MultiRegionScanResult",
]
