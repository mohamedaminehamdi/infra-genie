"""
Base Scanner Module
===================

Provides the abstract base class for all resource scanners in Infra-Genie.

This module defines the scanner interface that all resource-specific scanners
must implement, ensuring consistent behavior across different resource types.

Classes
-------
ScanResult
    Data class containing results from a scan operation.
BaseScanner
    Abstract base class for resource scanners.

Example
-------
>>> from src.core.base_scanner import BaseScanner, ScanResult
>>>
>>> class MyScanner(BaseScanner):
...     def get_resource_type(self) -> str:
...         return "my_resource"
...
...     def get_all_resources(self) -> list:
...         return [{"id": "res-1"}, {"id": "res-2"}]
...
...     def get_resources_in_use(self) -> set:
...         return {"res-1"}

Notes
-----
Scanner implementations should handle AWS API errors gracefully and
populate the `errors` field in ScanResult when issues occur.

See Also
--------
SecurityGroupScanner : Concrete implementation for security groups.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Set

# Module logger
logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """
    Data class representing the results of a resource scan.

    Contains comprehensive information about the scan including
    resource counts, unused resources, and any errors encountered.

    Parameters
    ----------
    resource_type : str
        Type of resource scanned (e.g., 'security_group', 'ebs_volume').
    region : str
        AWS region that was scanned.
    total_count : int
        Total number of resources found in the region.
    unused_count : int
        Number of resources identified as unused.
    unused_resources : list of dict
        Detailed information about each unused resource.
    scan_time : datetime, optional
        When the scan was performed (defaults to current time).
    errors : list of str, optional
        Any errors encountered during scanning.

    Attributes
    ----------
    resource_type : str
        Type of resource scanned.
    region : str
        AWS region scanned.
    total_count : int
        Total resources found.
    unused_count : int
        Unused resources found.
    unused_resources : list
        Details of unused resources.
    scan_time : datetime
        Scan timestamp.
    errors : list
        Errors encountered.

    Examples
    --------
    Creating a scan result:

    >>> result = ScanResult(
    ...     resource_type="security_group",
    ...     region="us-east-1",
    ...     total_count=50,
    ...     unused_count=5,
    ...     unused_resources=[
    ...         {"id": "sg-123", "name": "unused-sg"}
    ...     ]
    ... )

    Checking for errors:

    >>> if result.errors:
    ...     print(f"Scan completed with {len(result.errors)} errors")

    Serializing to dictionary:

    >>> data = result.to_dict()
    >>> import json
    >>> json.dumps(data)
    """

    resource_type: str
    region: str
    total_count: int
    unused_count: int
    unused_resources: List[Dict[str, Any]]
    scan_time: datetime = field(default_factory=datetime.utcnow)
    errors: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Validate fields after initialization."""
        if self.unused_count != len(self.unused_resources):
            logger.warning(
                f"unused_count ({self.unused_count}) doesn't match "
                f"unused_resources length ({len(self.unused_resources)})"
            )

    @property
    def has_errors(self) -> bool:
        """
        Check if the scan encountered any errors.

        Returns
        -------
        bool
            True if errors were encountered during scanning.
        """
        return len(self.errors) > 0

    @property
    def usage_percentage(self) -> float:
        """
        Calculate the percentage of resources in use.

        Returns
        -------
        float
            Percentage of resources in use (0-100).
        """
        if self.total_count == 0:
            return 100.0
        used_count = self.total_count - self.unused_count
        return (used_count / self.total_count) * 100

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert scan result to a dictionary for serialization.

        Returns
        -------
        dict
            Dictionary representation suitable for JSON serialization.

        Example
        -------
        >>> result = ScanResult(...)
        >>> data = result.to_dict()
        >>> json.dumps(data)
        """
        return {
            "resource_type": self.resource_type,
            "region": self.region,
            "total_count": self.total_count,
            "unused_count": self.unused_count,
            "unused_resources": self.unused_resources,
            "scan_time": self.scan_time.isoformat(),
            "errors": self.errors,
            "usage_percentage": round(self.usage_percentage, 2),
        }

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"ScanResult(resource_type='{self.resource_type}', "
            f"region='{self.region}', "
            f"total={self.total_count}, "
            f"unused={self.unused_count})"
        )


class BaseScanner(ABC):
    """
    Abstract base class for all resource scanners.

    Defines the interface that all scanner implementations must follow.
    Provides common functionality for scanning AWS resources and
    identifying unused items.

    Parameters
    ----------
    aws_client : AWSClient
        Instance of AWSClient for AWS API access.

    Attributes
    ----------
    aws_client : AWSClient
        The AWS client instance.
    region : str
        The AWS region being scanned.

    Methods
    -------
    scan()
        Perform a complete scan and return results.
    get_resource_type()
        Return the resource type identifier (abstract).
    get_all_resources()
        Fetch all resources of this type (abstract).
    get_resources_in_use()
        Get IDs of resources currently in use (abstract).
    get_unused_resources()
        Find resources not in use.

    Examples
    --------
    Implementing a custom scanner:

    >>> class EBSVolumeScanner(BaseScanner):
    ...     def get_resource_type(self) -> str:
    ...         return "ebs_volume"
    ...
    ...     def get_all_resources(self) -> List[Dict[str, Any]]:
    ...         # Fetch all EBS volumes
    ...         ec2 = self.aws_client.get_ec2_client()
    ...         response = ec2.describe_volumes()
    ...         return [{"id": v["VolumeId"]} for v in response["Volumes"]]
    ...
    ...     def get_resources_in_use(self) -> Set[str]:
    ...         # Find volumes that are attached
    ...         ec2 = self.aws_client.get_ec2_client()
    ...         response = ec2.describe_volumes(
    ...             Filters=[{"Name": "status", "Values": ["in-use"]}]
    ...         )
    ...         return {v["VolumeId"] for v in response["Volumes"]}

    Using a scanner:

    >>> scanner = EBSVolumeScanner(aws_client)
    >>> result = scanner.scan()
    >>> print(f"Found {result.unused_count} unused volumes")

    Notes
    -----
    Subclasses should implement robust error handling and populate
    the errors list in ScanResult when API calls fail.

    See Also
    --------
    SecurityGroupScanner : Example implementation.
    ScanResult : Return type for scan operations.
    """

    def __init__(self, aws_client) -> None:
        """
        Initialize the scanner.

        Parameters
        ----------
        aws_client : AWSClient
            Instance of AWSClient for AWS API access.
        """
        self.aws_client = aws_client
        self.region = aws_client.region
        logger.debug(
            f"Initialized {self.__class__.__name__} for region {self.region}"
        )

    @abstractmethod
    def get_resource_type(self) -> str:
        """
        Get the type of resource this scanner handles.

        Returns
        -------
        str
            String identifier for the resource type.
            Convention: lowercase with underscores (e.g., 'security_group').

        Example
        -------
        >>> scanner.get_resource_type()
        'security_group'
        """
        pass

    @abstractmethod
    def get_all_resources(self) -> List[Dict[str, Any]]:
        """
        Fetch all resources of this type in the region.

        Returns
        -------
        list of dict
            List of resource dictionaries. Each dict must contain
            at minimum an 'id' key with the resource identifier.

        Raises
        ------
        ResourceFetchError
            If unable to fetch resources from AWS.

        Example
        -------
        >>> resources = scanner.get_all_resources()
        >>> for r in resources:
        ...     print(r["id"])
        """
        pass

    @abstractmethod
    def get_resources_in_use(self) -> Set[str]:
        """
        Get the set of resource IDs that are currently in use.

        Returns
        -------
        set of str
            Set of resource IDs that are actively in use.

        Notes
        -----
        "In use" definition varies by resource type. For security groups,
        this means attached to an ENI, EC2, RDS, etc.

        Example
        -------
        >>> used_ids = scanner.get_resources_in_use()
        >>> print(f"{len(used_ids)} resources are in use")
        """
        pass

    def get_unused_resources(self) -> List[Dict[str, Any]]:
        """
        Find resources that are not in use.

        Compares all resources against those in use to identify
        unused resources.

        Returns
        -------
        list of dict
            List of unused resource dictionaries.

        Example
        -------
        >>> unused = scanner.get_unused_resources()
        >>> for r in unused:
        ...     print(f"Unused: {r['id']} ({r.get('name', 'unnamed')})")
        """
        all_resources = self.get_all_resources()
        used_ids = self.get_resources_in_use()

        unused = []
        for resource in all_resources:
            resource_id = resource.get("id")
            if resource_id and resource_id not in used_ids:
                unused.append(resource)

        logger.debug(
            f"Found {len(unused)} unused {self.get_resource_type()}s "
            f"out of {len(all_resources)} total"
        )

        return unused

    def scan(self) -> ScanResult:
        """
        Perform a complete scan and return results.

        This is the main entry point for scanning. It:
        1. Fetches all resources
        2. Identifies which are in use
        3. Computes the unused set
        4. Returns a comprehensive ScanResult

        Returns
        -------
        ScanResult
            Comprehensive scan results including counts and details.

        Example
        -------
        >>> result = scanner.scan()
        >>> print(f"Region: {result.region}")
        >>> print(f"Total: {result.total_count}")
        >>> print(f"Unused: {result.unused_count}")
        >>> if result.errors:
        ...     print(f"Errors: {result.errors}")
        """
        logger.info(f"Starting {self.get_resource_type()} scan in {self.region}")
        errors: List[str] = []

        # Fetch all resources
        try:
            all_resources = self.get_all_resources()
            total_count = len(all_resources)
            logger.debug(f"Found {total_count} total {self.get_resource_type()}s")
        except Exception as e:
            error_msg = f"Failed to get all resources: {e}"
            logger.error(error_msg)
            errors.append(error_msg)
            all_resources = []
            total_count = 0

        # Get resources in use
        try:
            used_ids = self.get_resources_in_use()
            logger.debug(f"Found {len(used_ids)} {self.get_resource_type()}s in use")
        except Exception as e:
            error_msg = f"Failed to get resources in use: {e}"
            logger.error(error_msg)
            errors.append(error_msg)
            used_ids = set()

        # Compute unused resources
        unused_resources = []
        for resource in all_resources:
            resource_id = resource.get("id")
            if resource_id and resource_id not in used_ids:
                unused_resources.append(resource)

        result = ScanResult(
            resource_type=self.get_resource_type(),
            region=self.region,
            total_count=total_count,
            unused_count=len(unused_resources),
            unused_resources=unused_resources,
            errors=errors,
        )

        logger.info(
            f"Scan complete: {result.unused_count}/{result.total_count} "
            f"{self.get_resource_type()}s unused in {self.region}"
        )

        return result

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"{self.__class__.__name__}("
            f"region='{self.region}', "
            f"resource_type='{self.get_resource_type()}')"
        )
