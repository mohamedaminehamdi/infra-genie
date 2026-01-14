"""
Cleaner for deleting unused AWS Security Groups.

Provides safe deletion with dry-run mode, confirmations, and error handling.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set

from botocore.exceptions import ClientError

from ..core.aws_client import AWSClient, AWSClientError


class DeleteStatus(Enum):
    """Status of a delete operation."""

    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    DRY_RUN = "dry_run"


@dataclass
class DeleteResult:
    """
    Result of a single security group deletion attempt.

    Attributes:
        sg_id: Security group ID
        sg_name: Security group name
        region: AWS region
        status: Result status
        error_message: Error message if failed
        timestamp: When the operation was attempted
    """

    sg_id: str
    sg_name: str
    region: str
    status: DeleteStatus
    error_message: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "sg_id": self.sg_id,
            "sg_name": self.sg_name,
            "region": self.region,
            "status": self.status.value,
            "error_message": self.error_message,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class DeleteSummary:
    """
    Summary of a batch delete operation.

    Attributes:
        total: Total number of security groups processed
        deleted: Number successfully deleted
        failed: Number that failed to delete
        skipped: Number skipped by user
        dry_run: Number processed in dry-run mode
        results: Individual results for each security group
        start_time: When the operation started
        end_time: When the operation completed
    """

    total: int = 0
    deleted: int = 0
    failed: int = 0
    skipped: int = 0
    dry_run: int = 0
    results: List[DeleteResult] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None

    def add_result(self, result: DeleteResult) -> None:
        """Add a result and update counts."""
        self.results.append(result)
        self.total += 1

        if result.status == DeleteStatus.SUCCESS:
            self.deleted += 1
        elif result.status == DeleteStatus.FAILED:
            self.failed += 1
        elif result.status == DeleteStatus.SKIPPED:
            self.skipped += 1
        elif result.status == DeleteStatus.DRY_RUN:
            self.dry_run += 1

    def complete(self) -> None:
        """Mark the operation as complete."""
        self.end_time = datetime.utcnow()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total": self.total,
            "deleted": self.deleted,
            "failed": self.failed,
            "skipped": self.skipped,
            "dry_run": self.dry_run,
            "results": [r.to_dict() for r in self.results],
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
        }


class SecurityGroupCleaner:
    """
    Cleaner for deleting unused security groups.

    Provides safe deletion with:
    - Dry-run mode (preview without deleting)
    - Interactive confirmation
    - Detailed error handling
    - Progress callbacks
    """

    # Common error codes and user-friendly messages
    ERROR_MESSAGES = {
        "DependencyViolation": "Security group is still in use by another resource",
        "InvalidGroup.NotFound": "Security group no longer exists",
        "InvalidGroup.InUse": "Security group is referenced by another security group",
        "UnauthorizedOperation": "Insufficient permissions to delete security group",
        "InvalidPermission.NotFound": "Security group rule not found",
    }

    def __init__(self, aws_client: AWSClient):
        """
        Initialize the cleaner.

        Args:
            aws_client: Instance of AWSClient
        """
        self.aws_client = aws_client
        self.region = aws_client.region
        self._ec2_client = None

    @property
    def ec2_client(self):
        """Lazy load EC2 client."""
        if self._ec2_client is None:
            self._ec2_client = self.aws_client.get_ec2_client()
        return self._ec2_client

    def delete_security_group(
        self,
        sg_id: str,
        sg_name: str,
        dry_run: bool = True,
    ) -> DeleteResult:
        """
        Delete a single security group.

        Args:
            sg_id: Security group ID
            sg_name: Security group name (for logging)
            dry_run: If True, only simulate deletion

        Returns:
            DeleteResult with operation status
        """
        if dry_run:
            return DeleteResult(
                sg_id=sg_id,
                sg_name=sg_name,
                region=self.region,
                status=DeleteStatus.DRY_RUN,
            )

        try:
            self.ec2_client.delete_security_group(GroupId=sg_id)
            return DeleteResult(
                sg_id=sg_id,
                sg_name=sg_name,
                region=self.region,
                status=DeleteStatus.SUCCESS,
            )
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            error_message = self.ERROR_MESSAGES.get(
                error_code, e.response.get("Error", {}).get("Message", str(e))
            )
            return DeleteResult(
                sg_id=sg_id,
                sg_name=sg_name,
                region=self.region,
                status=DeleteStatus.FAILED,
                error_message=error_message,
            )
        except Exception as e:
            return DeleteResult(
                sg_id=sg_id,
                sg_name=sg_name,
                region=self.region,
                status=DeleteStatus.FAILED,
                error_message=str(e),
            )

    def delete_batch(
        self,
        security_groups: List[Dict[str, Any]],
        dry_run: bool = True,
        progress_callback: Optional[Callable[[DeleteResult], None]] = None,
    ) -> DeleteSummary:
        """
        Delete multiple security groups.

        Args:
            security_groups: List of security group dicts with 'id' and 'name' keys
            dry_run: If True, only simulate deletion
            progress_callback: Optional callback called after each deletion

        Returns:
            DeleteSummary with results
        """
        summary = DeleteSummary()

        for sg in security_groups:
            sg_id = sg.get("id", "")
            sg_name = sg.get("name", "Unknown")

            result = self.delete_security_group(sg_id, sg_name, dry_run=dry_run)
            summary.add_result(result)

            if progress_callback:
                progress_callback(result)

        summary.complete()
        return summary

    def delete_with_confirmation(
        self,
        security_groups: List[Dict[str, Any]],
        confirm_callback: Callable[[Dict[str, Any]], bool],
        dry_run: bool = False,
        progress_callback: Optional[Callable[[DeleteResult], None]] = None,
    ) -> DeleteSummary:
        """
        Delete security groups with individual confirmation.

        Args:
            security_groups: List of security group dicts
            confirm_callback: Callback that returns True to delete, False to skip
            dry_run: If True, only simulate deletion
            progress_callback: Optional callback called after each deletion

        Returns:
            DeleteSummary with results
        """
        summary = DeleteSummary()

        for sg in security_groups:
            sg_id = sg.get("id", "")
            sg_name = sg.get("name", "Unknown")

            # Ask for confirmation
            if not confirm_callback(sg):
                result = DeleteResult(
                    sg_id=sg_id,
                    sg_name=sg_name,
                    region=self.region,
                    status=DeleteStatus.SKIPPED,
                )
            else:
                result = self.delete_security_group(sg_id, sg_name, dry_run=dry_run)

            summary.add_result(result)

            if progress_callback:
                progress_callback(result)

        summary.complete()
        return summary

    @staticmethod
    def can_delete(sg: Dict[str, Any]) -> tuple:
        """
        Check if a security group can be deleted.

        Args:
            sg: Security group dict

        Returns:
            Tuple of (can_delete: bool, reason: str)
        """
        # Can't delete default security groups
        if sg.get("is_default", False) or sg.get("name") == "default":
            return False, "Default security groups cannot be deleted"

        return True, ""
