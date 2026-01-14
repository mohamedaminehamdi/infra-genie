"""
Abstract base class for resource scanners.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class ScanResult:
    """
    Represents the result of a resource scan.

    Attributes:
        resource_type: Type of resource scanned (e.g., 'security_group')
        region: AWS region that was scanned
        total_count: Total number of resources found
        unused_count: Number of unused resources found
        unused_resources: List of unused resource details
        scan_time: When the scan was performed
        errors: Any errors encountered during scanning
    """

    resource_type: str
    region: str
    total_count: int
    unused_count: int
    unused_resources: List[Dict[str, Any]]
    scan_time: datetime = field(default_factory=datetime.utcnow)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert scan result to dictionary."""
        return {
            "resource_type": self.resource_type,
            "region": self.region,
            "total_count": self.total_count,
            "unused_count": self.unused_count,
            "unused_resources": self.unused_resources,
            "scan_time": self.scan_time.isoformat(),
            "errors": self.errors,
        }


class BaseScanner(ABC):
    """
    Abstract base class for all resource scanners.

    All scanner modules should extend this class and implement
    the required methods to ensure consistent behavior.
    """

    def __init__(self, aws_client):
        """
        Initialize the scanner.

        Args:
            aws_client: Instance of AWSClient for AWS API access
        """
        self.aws_client = aws_client
        self.region = aws_client.region

    @abstractmethod
    def get_resource_type(self) -> str:
        """
        Get the type of resource this scanner handles.

        Returns:
            String identifier for the resource type (e.g., 'security_group')
        """
        pass

    @abstractmethod
    def get_all_resources(self) -> List[Dict[str, Any]]:
        """
        Fetch all resources of this type in the region.

        Returns:
            List of resource dictionaries with relevant fields
        """
        pass

    @abstractmethod
    def get_resources_in_use(self) -> set:
        """
        Get the set of resource IDs that are currently in use.

        Returns:
            Set of resource IDs that are in use
        """
        pass

    def get_unused_resources(self) -> List[Dict[str, Any]]:
        """
        Find resources that are not in use.

        Returns:
            List of unused resource dictionaries
        """
        all_resources = self.get_all_resources()
        used_ids = self.get_resources_in_use()

        unused = []
        for resource in all_resources:
            resource_id = resource.get("id")
            if resource_id and resource_id not in used_ids:
                unused.append(resource)

        return unused

    def scan(self) -> ScanResult:
        """
        Perform a complete scan and return results.

        Returns:
            ScanResult containing scan details and unused resources
        """
        errors = []

        try:
            all_resources = self.get_all_resources()
            total_count = len(all_resources)
        except Exception as e:
            errors.append(f"Failed to get all resources: {str(e)}")
            all_resources = []
            total_count = 0

        try:
            used_ids = self.get_resources_in_use()
        except Exception as e:
            errors.append(f"Failed to get resources in use: {str(e)}")
            used_ids = set()

        unused_resources = []
        for resource in all_resources:
            resource_id = resource.get("id")
            if resource_id and resource_id not in used_ids:
                unused_resources.append(resource)

        return ScanResult(
            resource_type=self.get_resource_type(),
            region=self.region,
            total_count=total_count,
            unused_count=len(unused_resources),
            unused_resources=unused_resources,
            errors=errors,
        )
