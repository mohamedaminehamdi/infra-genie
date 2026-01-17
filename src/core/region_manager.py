"""
Region Manager Module
=====================

Provides multi-region orchestration for scanning AWS resources across
all available regions in parallel.

This module handles:
- Dynamic discovery of available AWS regions
- Parallel execution of scans using thread pools
- Aggregation of results from multiple regions
- Progress tracking and error handling

Classes
-------
MultiRegionScanResult
    Aggregated results from scanning multiple regions.
RegionManager
    Orchestrates multi-region scanning operations.

Example
-------
>>> from src.core.region_manager import RegionManager
>>> from src.scanners import SecurityGroupScanner
>>>
>>> manager = RegionManager(profile="production", max_workers=10)
>>> regions = manager.get_all_regions()
>>> result = manager.scan_regions(SecurityGroupScanner, regions=regions)
>>> print(f"Found {result.total_unused} unused resources across {len(regions)} regions")

Notes
-----
The RegionManager uses ThreadPoolExecutor for parallel scanning.
Each region scan runs in its own thread with an independent AWS client.

See Also
--------
AWSClient : Client used for each region.
BaseScanner : Scanner interface.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Type

from src.core.aws_client import AWSClient
from src.core.base_scanner import BaseScanner, ScanResult
from src.core.exceptions import AWSClientError

# Module logger
logger = logging.getLogger(__name__)


@dataclass
class MultiRegionScanResult:
    """
    Aggregated results from scanning multiple AWS regions.

    Contains comprehensive data from a multi-region scan operation
    including per-region results, totals, and error information.

    Parameters
    ----------
    resource_type : str
        Type of resource that was scanned.
    regions_scanned : list of str
        List of regions that were scanned.
    total_resources : int
        Total resources found across all regions.
    total_unused : int
        Total unused resources found across all regions.
    results_by_region : dict
        Mapping of region name to ScanResult.
    scan_time : datetime, optional
        When the scan was performed.
    errors : dict, optional
        Mapping of region name to list of error messages.

    Examples
    --------
    Accessing aggregated results:

    >>> result = manager.scan_regions(SecurityGroupScanner)
    >>> print(f"Scanned {len(result.regions_scanned)} regions")
    >>> print(f"Total unused: {result.total_unused}")

    Getting all unused resources:

    >>> all_unused = result.get_all_unused_resources()
    >>> for resource in all_unused:
    ...     print(f"{resource['region']}: {resource['id']}")

    Checking for regional errors:

    >>> if result.errors:
    ...     for region, errors in result.errors.items():
    ...         print(f"{region}: {errors}")
    """

    resource_type: str
    regions_scanned: List[str]
    total_resources: int
    total_unused: int
    results_by_region: Dict[str, ScanResult]
    scan_time: datetime = field(default_factory=datetime.utcnow)
    errors: Dict[str, List[str]] = field(default_factory=dict)

    @property
    def has_errors(self) -> bool:
        """
        Check if any region encountered errors.

        Returns
        -------
        bool
            True if any region had errors during scanning.
        """
        return len(self.errors) > 0

    @property
    def successful_regions(self) -> List[str]:
        """
        Get list of regions that scanned successfully.

        Returns
        -------
        list of str
            Region names that completed without errors.
        """
        return [r for r in self.regions_scanned if r not in self.errors]

    @property
    def failed_regions(self) -> List[str]:
        """
        Get list of regions that had errors.

        Returns
        -------
        list of str
            Region names that encountered errors.
        """
        return list(self.errors.keys())

    @property
    def usage_percentage(self) -> float:
        """
        Calculate overall resource usage percentage.

        Returns
        -------
        float
            Percentage of resources in use across all regions.
        """
        if self.total_resources == 0:
            return 100.0
        used = self.total_resources - self.total_unused
        return (used / self.total_resources) * 100

    def get_all_unused_resources(self) -> List[Dict[str, Any]]:
        """
        Get all unused resources across all regions.

        Each resource dictionary is augmented with a 'region' key
        indicating which region it came from.

        Returns
        -------
        list of dict
            All unused resources with region information.

        Example
        -------
        >>> resources = result.get_all_unused_resources()
        >>> for r in resources:
        ...     print(f"{r['region']}: {r['id']} - {r.get('name', 'unnamed')}")
        """
        all_unused = []
        for region, scan_result in self.results_by_region.items():
            for resource in scan_result.unused_resources:
                resource_with_region = resource.copy()
                resource_with_region["region"] = region
                all_unused.append(resource_with_region)
        return all_unused

    def get_region_summary(self) -> Dict[str, Dict[str, int]]:
        """
        Get a summary of results per region.

        Returns
        -------
        dict
            Mapping of region to summary statistics.

        Example
        -------
        >>> summary = result.get_region_summary()
        >>> for region, stats in summary.items():
        ...     print(f"{region}: {stats['unused']}/{stats['total']}")
        """
        return {
            region: {
                "total": r.total_count,
                "unused": r.unused_count,
                "used": r.total_count - r.unused_count,
            }
            for region, r in self.results_by_region.items()
        }

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary for serialization.

        Returns
        -------
        dict
            Dictionary representation suitable for JSON serialization.
        """
        return {
            "resource_type": self.resource_type,
            "regions_scanned": self.regions_scanned,
            "total_resources": self.total_resources,
            "total_unused": self.total_unused,
            "usage_percentage": round(self.usage_percentage, 2),
            "results_by_region": {
                region: result.to_dict()
                for region, result in self.results_by_region.items()
            },
            "scan_time": self.scan_time.isoformat(),
            "errors": self.errors,
        }

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"MultiRegionScanResult("
            f"resource_type='{self.resource_type}', "
            f"regions={len(self.regions_scanned)}, "
            f"total_unused={self.total_unused})"
        )


class RegionManager:
    """
    Manages multi-region scanning operations.

    Provides functionality for:
    - Discovering available AWS regions
    - Executing scans in parallel across regions
    - Aggregating and reporting results
    - Handling region-specific errors

    Parameters
    ----------
    profile : str, optional
        AWS profile name from ~/.aws/credentials.
    max_workers : int, default=10
        Maximum number of parallel region scans.
    max_retries : int, default=3
        Maximum retries for failed API calls.
    timeout : int, default=30
        Request timeout in seconds.

    Attributes
    ----------
    profile : str or None
        The configured AWS profile.
    max_workers : int
        Maximum parallel workers.
    max_retries : int
        Maximum API retry attempts.
    timeout : int
        Request timeout.

    Examples
    --------
    Basic multi-region scan:

    >>> manager = RegionManager(profile="production")
    >>> result = manager.scan_regions(SecurityGroupScanner)
    >>> print(f"Found {result.total_unused} unused security groups")

    Scanning specific regions:

    >>> regions = ["us-east-1", "us-west-2", "eu-west-1"]
    >>> result = manager.scan_regions(SecurityGroupScanner, regions=regions)

    With progress tracking:

    >>> def on_progress(region, status):
    ...     print(f"{region}: {status}")
    ...
    >>> result = manager.scan_regions(
    ...     SecurityGroupScanner,
    ...     progress_callback=on_progress
    ... )

    Notes
    -----
    Each region scan runs in its own thread with a dedicated AWS client.
    This ensures thread safety and prevents credential caching issues.

    See Also
    --------
    AWSClient : Client created for each region.
    BaseScanner : Scanner interface.
    """

    def __init__(
        self,
        profile: Optional[str] = None,
        max_workers: int = 10,
        max_retries: int = 3,
        timeout: int = 30,
    ) -> None:
        """Initialize region manager with the specified configuration."""
        self.profile = profile
        self.max_workers = max_workers
        self.max_retries = max_retries
        self.timeout = timeout

        # Base client for fetching region list (us-east-1 is always available)
        self._base_client = AWSClient(
            region="us-east-1",
            profile=profile,
            max_retries=max_retries,
            timeout=timeout,
        )

        logger.debug(
            f"Initialized RegionManager with max_workers={max_workers}"
        )

    def get_all_regions(self) -> List[str]:
        """
        Fetch all available AWS regions.

        Returns
        -------
        list of str
            Sorted list of available region names.

        Raises
        ------
        AWSClientError
            If unable to fetch the region list.

        Example
        -------
        >>> manager = RegionManager()
        >>> regions = manager.get_all_regions()
        >>> print(f"Found {len(regions)} regions")
        >>> print(regions[:5])
        ['ap-east-1', 'ap-northeast-1', 'ap-northeast-2', ...]
        """
        try:
            ec2 = self._base_client.get_ec2_client()
            response = ec2.describe_regions(AllRegions=False)
            regions = sorted([r["RegionName"] for r in response["Regions"]])
            logger.info(f"Discovered {len(regions)} available AWS regions")
            return regions
        except Exception as e:
            logger.exception("Failed to fetch AWS regions")
            raise AWSClientError(f"Failed to fetch AWS regions: {e}")

    def get_client_for_region(self, region: str) -> AWSClient:
        """
        Create an AWSClient configured for a specific region.

        Parameters
        ----------
        region : str
            AWS region name.

        Returns
        -------
        AWSClient
            Client instance for the specified region.

        Example
        -------
        >>> client = manager.get_client_for_region("eu-west-1")
        >>> print(client.region)
        'eu-west-1'
        """
        return AWSClient(
            region=region,
            profile=self.profile,
            max_retries=self.max_retries,
            timeout=self.timeout,
        )

    def _scan_region(
        self,
        region: str,
        scanner_class: Type[BaseScanner],
        progress_callback: Optional[Callable[[str, str], None]] = None,
    ) -> tuple:
        """
        Scan a single region (internal method).

        Parameters
        ----------
        region : str
            AWS region to scan.
        scanner_class : type
            Scanner class to instantiate.
        progress_callback : callable, optional
            Callback for progress updates.

        Returns
        -------
        tuple
            (region, ScanResult or None, error message or None)
        """
        try:
            if progress_callback:
                progress_callback(region, "scanning")

            client = self.get_client_for_region(region)
            scanner = scanner_class(client)
            result = scanner.scan()

            if progress_callback:
                progress_callback(region, "complete")

            logger.debug(f"Completed scan of {region}")
            return (region, result, None)

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error scanning {region}: {error_msg}")
            if progress_callback:
                progress_callback(region, "error")
            return (region, None, error_msg)

    def scan_regions(
        self,
        scanner_class: Type[BaseScanner],
        regions: Optional[List[str]] = None,
        progress_callback: Optional[Callable[[str, str], None]] = None,
    ) -> MultiRegionScanResult:
        """
        Scan multiple regions in parallel.

        Parameters
        ----------
        scanner_class : type
            Scanner class to use (must extend BaseScanner).
        regions : list of str, optional
            Regions to scan. If None, scans all available regions.
        progress_callback : callable, optional
            Function called with (region, status) for progress updates.
            Status is one of: 'scanning', 'complete', 'error'.

        Returns
        -------
        MultiRegionScanResult
            Aggregated results from all regions.

        Examples
        --------
        Scan all regions:

        >>> result = manager.scan_regions(SecurityGroupScanner)

        Scan specific regions:

        >>> result = manager.scan_regions(
        ...     SecurityGroupScanner,
        ...     regions=["us-east-1", "eu-west-1"]
        ... )

        With progress tracking:

        >>> def progress(region, status):
        ...     print(f"{region}: {status}")
        >>> result = manager.scan_regions(
        ...     SecurityGroupScanner,
        ...     progress_callback=progress
        ... )
        """
        if regions is None:
            regions = self.get_all_regions()

        logger.info(f"Starting multi-region scan across {len(regions)} regions")

        # Initialize result containers
        results_by_region: Dict[str, ScanResult] = {}
        errors: Dict[str, List[str]] = {}
        total_resources = 0
        total_unused = 0

        # Get resource type from a temporary scanner
        temp_client = self.get_client_for_region(regions[0] if regions else "us-east-1")
        temp_scanner = scanner_class(temp_client)
        resource_type = temp_scanner.get_resource_type()

        # Execute scans in parallel
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(
                    self._scan_region, region, scanner_class, progress_callback
                ): region
                for region in regions
            }

            for future in as_completed(futures):
                region, result, error = future.result()

                if error:
                    errors[region] = [error]
                    logger.warning(f"Region {region} failed: {error}")
                elif result:
                    results_by_region[region] = result
                    total_resources += result.total_count
                    total_unused += result.unused_count
                    if result.errors:
                        errors[region] = result.errors

        logger.info(
            f"Multi-region scan complete: {total_unused} unused "
            f"out of {total_resources} total across {len(results_by_region)} regions"
        )

        return MultiRegionScanResult(
            resource_type=resource_type,
            regions_scanned=regions,
            total_resources=total_resources,
            total_unused=total_unused,
            results_by_region=results_by_region,
            errors=errors,
        )

    def scan_single_region(
        self,
        scanner_class: Type[BaseScanner],
        region: str,
    ) -> ScanResult:
        """
        Scan a single region (convenience method).

        Parameters
        ----------
        scanner_class : type
            Scanner class to use.
        region : str
            AWS region to scan.

        Returns
        -------
        ScanResult
            Scan results for the region.

        Example
        -------
        >>> result = manager.scan_single_region(SecurityGroupScanner, "us-east-1")
        >>> print(f"Found {result.unused_count} unused resources")
        """
        client = self.get_client_for_region(region)
        scanner = scanner_class(client)
        return scanner.scan()

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"RegionManager(profile={self.profile!r}, "
            f"max_workers={self.max_workers})"
        )
