"""
Region manager for multi-region scanning operations.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Type

from .aws_client import AWSClient, AWSClientError
from .base_scanner import BaseScanner, ScanResult


@dataclass
class MultiRegionScanResult:
    """
    Aggregated results from scanning multiple regions.

    Attributes:
        resource_type: Type of resource scanned
        regions_scanned: List of regions that were scanned
        total_resources: Total resources across all regions
        total_unused: Total unused resources across all regions
        results_by_region: Individual ScanResult for each region
        scan_time: When the scan was performed
        errors: Region-level errors encountered
    """

    resource_type: str
    regions_scanned: List[str]
    total_resources: int
    total_unused: int
    results_by_region: Dict[str, ScanResult]
    scan_time: datetime = field(default_factory=datetime.utcnow)
    errors: Dict[str, List[str]] = field(default_factory=dict)

    def get_all_unused_resources(self) -> List[Dict[str, Any]]:
        """
        Get all unused resources across all regions.

        Returns:
            List of unused resources with region information
        """
        all_unused = []
        for region, result in self.results_by_region.items():
            for resource in result.unused_resources:
                resource_with_region = resource.copy()
                resource_with_region["region"] = region
                all_unused.append(resource_with_region)
        return all_unused

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "resource_type": self.resource_type,
            "regions_scanned": self.regions_scanned,
            "total_resources": self.total_resources,
            "total_unused": self.total_unused,
            "results_by_region": {
                region: result.to_dict()
                for region, result in self.results_by_region.items()
            },
            "scan_time": self.scan_time.isoformat(),
            "errors": self.errors,
        }


class RegionManager:
    """
    Manages multi-region scanning operations.

    Handles fetching available regions and orchestrating
    parallel scanning across multiple regions.
    """

    def __init__(
        self,
        profile: Optional[str] = None,
        max_workers: int = 10,
        max_retries: int = 3,
        timeout: int = 30,
    ):
        """
        Initialize region manager.

        Args:
            profile: AWS profile name from ~/.aws/credentials
            max_workers: Maximum number of parallel region scans
            max_retries: Maximum retries for failed API calls
            timeout: Request timeout in seconds
        """
        self.profile = profile
        self.max_workers = max_workers
        self.max_retries = max_retries
        self.timeout = timeout
        # Use us-east-1 as default region to fetch region list
        self._base_client = AWSClient(
            region="us-east-1",
            profile=profile,
            max_retries=max_retries,
            timeout=timeout,
        )

    def get_all_regions(self) -> List[str]:
        """
        Fetch all available AWS regions.

        Returns:
            List of region names

        Raises:
            AWSClientError: If unable to fetch regions
        """
        try:
            ec2 = self._base_client.get_ec2_client()
            response = ec2.describe_regions(AllRegions=False)
            regions = [region["RegionName"] for region in response["Regions"]]
            return sorted(regions)
        except Exception as e:
            raise AWSClientError(f"Failed to fetch AWS regions: {str(e)}")

    def get_client_for_region(self, region: str) -> AWSClient:
        """
        Get an AWSClient configured for a specific region.

        Args:
            region: AWS region name

        Returns:
            AWSClient instance for the specified region
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
        Scan a single region.

        Args:
            region: AWS region to scan
            scanner_class: Scanner class to use
            progress_callback: Optional callback for progress updates

        Returns:
            Tuple of (region, ScanResult or None, error or None)
        """
        try:
            if progress_callback:
                progress_callback(region, "scanning")

            client = self.get_client_for_region(region)
            scanner = scanner_class(client)
            result = scanner.scan()

            if progress_callback:
                progress_callback(region, "complete")

            return (region, result, None)
        except Exception as e:
            if progress_callback:
                progress_callback(region, "error")
            return (region, None, str(e))

    def scan_regions(
        self,
        scanner_class: Type[BaseScanner],
        regions: Optional[List[str]] = None,
        progress_callback: Optional[Callable[[str, str], None]] = None,
    ) -> MultiRegionScanResult:
        """
        Scan multiple regions in parallel.

        Args:
            scanner_class: Scanner class to use for scanning
            regions: List of regions to scan (None for all regions)
            progress_callback: Optional callback(region, status) for progress updates

        Returns:
            MultiRegionScanResult with aggregated results
        """
        if regions is None:
            regions = self.get_all_regions()

        results_by_region: Dict[str, ScanResult] = {}
        errors: Dict[str, List[str]] = {}
        total_resources = 0
        total_unused = 0

        # Create a temporary scanner to get resource type
        temp_client = self.get_client_for_region(regions[0] if regions else "us-east-1")
        temp_scanner = scanner_class(temp_client)
        resource_type = temp_scanner.get_resource_type()

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
                elif result:
                    results_by_region[region] = result
                    total_resources += result.total_count
                    total_unused += result.unused_count
                    if result.errors:
                        errors[region] = result.errors

        return MultiRegionScanResult(
            resource_type=resource_type,
            regions_scanned=regions,
            total_resources=total_resources,
            total_unused=total_unused,
            results_by_region=results_by_region,
            errors=errors,
        )

    def scan_single_region(
        self, scanner_class: Type[BaseScanner], region: str
    ) -> ScanResult:
        """
        Scan a single region.

        Args:
            scanner_class: Scanner class to use
            region: AWS region to scan

        Returns:
            ScanResult for the region
        """
        client = self.get_client_for_region(region)
        scanner = scanner_class(client)
        return scanner.scan()
