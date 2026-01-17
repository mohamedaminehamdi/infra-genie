"""
Core Infrastructure Components
==============================

This module provides the foundational components for Infra-Genie:

- :class:`AWSClient` - Manages AWS connections and client creation
- :class:`BaseScanner` - Abstract base class for resource scanners
- :class:`RegionManager` - Orchestrates multi-region operations
- Exception hierarchy for error handling

Classes
-------
AWSClient
    Thread-safe AWS client wrapper with retry logic and credential management.
BaseScanner
    Abstract base class defining the scanner interface.
ScanResult
    Data class containing scan results.
RegionManager
    Manages parallel scanning across multiple AWS regions.
MultiRegionScanResult
    Aggregated results from multi-region scans.

Exceptions
----------
InfraGenieError
    Base exception for all Infra-Genie errors.
AWSClientError
    Base exception for AWS client errors.
CredentialsError
    Raised when credentials are invalid or missing.
RegionError
    Raised when region is invalid.
ServiceError
    Raised when AWS service access fails.
ScannerError
    Base exception for scanner errors.
CleanerError
    Base exception for cleaner errors.

Example
-------
>>> from src.core import AWSClient, RegionManager
>>>
>>> # Single region client
>>> client = AWSClient(region="us-east-1", profile="production")
>>>
>>> # Multi-region scanning
>>> manager = RegionManager(profile="production", max_workers=10)
>>> regions = manager.get_all_regions()

See Also
--------
src.scanners : Resource scanner implementations.
src.cleaners : Resource cleaner implementations.
src.reporters : Output formatters.
"""

from src.core.aws_client import AWSClient
from src.core.base_scanner import BaseScanner, ScanResult
from src.core.exceptions import (
    AWSClientError,
    CleanerError,
    CredentialsError,
    DeleteError,
    DependencyError,
    InfraGenieError,
    RegionError,
    ResourceFetchError,
    ScannerError,
    ScanTimeoutError,
    ServiceError,
)
from src.core.region_manager import MultiRegionScanResult, RegionManager

__all__ = [
    # Client
    "AWSClient",
    # Scanner base
    "BaseScanner",
    "ScanResult",
    # Region management
    "RegionManager",
    "MultiRegionScanResult",
    # Exceptions - Base
    "InfraGenieError",
    # Exceptions - AWS Client
    "AWSClientError",
    "CredentialsError",
    "RegionError",
    "ServiceError",
    # Exceptions - Scanner
    "ScannerError",
    "ResourceFetchError",
    "ScanTimeoutError",
    # Exceptions - Cleaner
    "CleanerError",
    "DeleteError",
    "DependencyError",
]
