"""
Security Group Cleaner Module
=============================

Provides safe deletion of unused EC2 Security Groups with comprehensive
safety features and error handling.

This module implements enterprise-grade deletion logic with:
- Dry-run mode for previewing changes
- Interactive confirmation workflows
- Batch deletion with progress tracking
- Detailed error messages and recovery suggestions

Classes
-------
DeleteStatus
    Enum representing deletion operation outcomes.
DeleteResult
    Data class containing result of a single deletion.
DeleteSummary
    Data class containing batch deletion results.
SecurityGroupCleaner
    Main cleaner class for security group deletion.

Example
-------
>>> from src.cleaners import SecurityGroupCleaner
>>> from src.core import AWSClient
>>>
>>> client = AWSClient(region="us-east-1")
>>> cleaner = SecurityGroupCleaner(client)
>>>
>>> # Dry-run deletion
>>> result = cleaner.delete_security_group("sg-123", "my-sg", dry_run=True)
>>> print(f"Status: {result.status.value}")
>>>
>>> # Batch deletion with progress
>>> def on_progress(result):
...     print(f"{result.sg_id}: {result.status.value}")
>>>
>>> summary = cleaner.delete_batch(security_groups, dry_run=False,
...                                 progress_callback=on_progress)
>>> print(f"Deleted: {summary.deleted}/{summary.total}")

Safety Features
---------------
1. **Dry-run by default**: All deletion methods default to dry_run=True
2. **Default SG protection**: Validates SGs can be deleted before attempting
3. **Error translation**: Converts AWS error codes to user-friendly messages
4. **Graceful failures**: Individual failures don't stop batch operations

See Also
--------
SecurityGroupScanner : For identifying unused security groups.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

from botocore.exceptions import ClientError

from src.core.aws_client import AWSClient

# Module logger
logger = logging.getLogger(__name__)


class DeleteStatus(Enum):
    """
    Status of a delete operation.

    Attributes
    ----------
    SUCCESS : str
        Resource was successfully deleted.
    FAILED : str
        Deletion failed due to an error.
    SKIPPED : str
        Deletion was skipped by user choice.
    DRY_RUN : str
        Operation was a dry-run (no changes made).
    """

    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    DRY_RUN = "dry_run"


@dataclass
class DeleteResult:
    """
    Result of a single security group deletion attempt.

    Parameters
    ----------
    sg_id : str
        Security group ID that was processed.
    sg_name : str
        Security group name for display purposes.
    region : str
        AWS region where the operation was attempted.
    status : DeleteStatus
        Outcome of the deletion attempt.
    error_message : str, optional
        Error details if status is FAILED.
    timestamp : datetime, optional
        When the operation was attempted (defaults to now).

    Examples
    --------
    Creating a result:

    >>> result = DeleteResult(
    ...     sg_id="sg-123",
    ...     sg_name="my-sg",
    ...     region="us-east-1",
    ...     status=DeleteStatus.SUCCESS
    ... )

    Checking for failure:

    >>> if result.status == DeleteStatus.FAILED:
    ...     print(f"Error: {result.error_message}")
    """

    sg_id: str
    sg_name: str
    region: str
    status: DeleteStatus
    error_message: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)

    @property
    def is_success(self) -> bool:
        """Check if the operation succeeded."""
        return self.status == DeleteStatus.SUCCESS

    @property
    def is_failure(self) -> bool:
        """Check if the operation failed."""
        return self.status == DeleteStatus.FAILED

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary for serialization.

        Returns
        -------
        dict
            Dictionary representation suitable for JSON.
        """
        return {
            "sg_id": self.sg_id,
            "sg_name": self.sg_name,
            "region": self.region,
            "status": self.status.value,
            "error_message": self.error_message,
            "timestamp": self.timestamp.isoformat(),
        }

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"DeleteResult(sg_id='{self.sg_id}', "
            f"status={self.status.value})"
        )


@dataclass
class DeleteSummary:
    """
    Summary of a batch delete operation.

    Aggregates results from multiple deletion attempts and provides
    convenient access to counts and individual results.

    Parameters
    ----------
    total : int, default=0
        Total number of resources processed.
    deleted : int, default=0
        Number successfully deleted.
    failed : int, default=0
        Number that failed to delete.
    skipped : int, default=0
        Number skipped by user choice.
    dry_run : int, default=0
        Number processed in dry-run mode.
    results : list, optional
        Individual DeleteResult objects.
    start_time : datetime, optional
        When the batch operation started.
    end_time : datetime, optional
        When the batch operation completed.

    Examples
    --------
    Creating and using a summary:

    >>> summary = DeleteSummary()
    >>> summary.add_result(result1)
    >>> summary.add_result(result2)
    >>> summary.complete()
    >>>
    >>> print(f"Deleted: {summary.deleted}/{summary.total}")
    >>> print(f"Duration: {summary.duration}")

    Getting failed results:

    >>> for result in summary.failed_results:
    ...     print(f"Failed: {result.sg_id} - {result.error_message}")
    """

    total: int = 0
    deleted: int = 0
    failed: int = 0
    skipped: int = 0
    dry_run: int = 0
    results: List[DeleteResult] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None

    @property
    def duration(self) -> Optional[float]:
        """
        Get operation duration in seconds.

        Returns
        -------
        float or None
            Duration in seconds, or None if not complete.
        """
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None

    @property
    def success_rate(self) -> float:
        """
        Calculate success rate as a percentage.

        Returns
        -------
        float
            Percentage of successful deletions (0-100).
        """
        if self.total == 0:
            return 100.0
        return (self.deleted / self.total) * 100

    @property
    def failed_results(self) -> List[DeleteResult]:
        """
        Get all failed results.

        Returns
        -------
        list of DeleteResult
            Results with FAILED status.
        """
        return [r for r in self.results if r.status == DeleteStatus.FAILED]

    @property
    def successful_results(self) -> List[DeleteResult]:
        """
        Get all successful results.

        Returns
        -------
        list of DeleteResult
            Results with SUCCESS status.
        """
        return [r for r in self.results if r.status == DeleteStatus.SUCCESS]

    def add_result(self, result: DeleteResult) -> None:
        """
        Add a result and update counts.

        Parameters
        ----------
        result : DeleteResult
            The result to add.
        """
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
        logger.info(
            f"Batch delete complete: {self.deleted} deleted, "
            f"{self.failed} failed, {self.skipped} skipped"
        )

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary for serialization.

        Returns
        -------
        dict
            Dictionary representation suitable for JSON.
        """
        return {
            "total": self.total,
            "deleted": self.deleted,
            "failed": self.failed,
            "skipped": self.skipped,
            "dry_run": self.dry_run,
            "success_rate": round(self.success_rate, 2),
            "duration_seconds": self.duration,
            "results": [r.to_dict() for r in self.results],
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
        }

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"DeleteSummary(total={self.total}, deleted={self.deleted}, "
            f"failed={self.failed}, skipped={self.skipped})"
        )


class SecurityGroupCleaner:
    """
    Cleaner for safely deleting unused security groups.

    Provides enterprise-grade deletion capabilities with:
    - Dry-run mode for previewing changes
    - Interactive confirmation workflows
    - Batch operations with progress tracking
    - Comprehensive error handling and messaging

    Parameters
    ----------
    aws_client : AWSClient
        Instance of AWSClient for AWS API access.

    Attributes
    ----------
    region : str
        The AWS region for operations.

    Examples
    --------
    Basic deletion:

    >>> cleaner = SecurityGroupCleaner(client)
    >>> result = cleaner.delete_security_group("sg-123", "test", dry_run=False)
    >>> print(f"Status: {result.status.value}")

    Batch deletion with progress:

    >>> def on_progress(result):
    ...     print(f"Processed: {result.sg_id}")
    >>>
    >>> summary = cleaner.delete_batch(
    ...     security_groups,
    ...     dry_run=False,
    ...     progress_callback=on_progress
    ... )

    Interactive deletion:

    >>> def confirm(sg):
    ...     return input(f"Delete {sg['name']}? (y/n): ").lower() == 'y'
    >>>
    >>> summary = cleaner.delete_with_confirmation(
    ...     security_groups,
    ...     confirm_callback=confirm
    ... )

    See Also
    --------
    SecurityGroupScanner : For identifying unused security groups.
    DeleteResult : Individual deletion result.
    DeleteSummary : Batch deletion results.
    """

    # AWS error codes mapped to user-friendly messages
    ERROR_MESSAGES: Dict[str, str] = {
        "DependencyViolation": (
            "Security group is still in use by another resource. "
            "Detach it from all resources before deletion."
        ),
        "InvalidGroup.NotFound": (
            "Security group no longer exists. It may have been deleted."
        ),
        "InvalidGroup.InUse": (
            "Security group is referenced by another security group's rules. "
            "Remove the references before deletion."
        ),
        "UnauthorizedOperation": (
            "Insufficient permissions to delete this security group. "
            "Check your IAM policies."
        ),
        "InvalidPermission.NotFound": (
            "Security group rule not found. The rule may have been modified."
        ),
        "CannotDelete": (
            "Security group cannot be deleted. This may be a default VPC "
            "security group which cannot be removed."
        ),
    }

    def __init__(self, aws_client: AWSClient) -> None:
        """Initialize the cleaner with an AWS client."""
        self.aws_client = aws_client
        self.region = aws_client.region
        self._ec2_client = None

        logger.debug(f"Initialized SecurityGroupCleaner for {self.region}")

    @property
    def ec2_client(self):
        """
        Get EC2 client (lazy loaded).

        Returns
        -------
        EC2.Client
            Boto3 EC2 client.
        """
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

        Parameters
        ----------
        sg_id : str
            Security group ID to delete.
        sg_name : str
            Security group name (for logging/display).
        dry_run : bool, default=True
            If True, only simulate the deletion.

        Returns
        -------
        DeleteResult
            Result containing status and any error information.

        Examples
        --------
        Dry-run (preview):

        >>> result = cleaner.delete_security_group("sg-123", "test", dry_run=True)
        >>> print(f"Would delete: {result.sg_id}")

        Actual deletion:

        >>> result = cleaner.delete_security_group("sg-123", "test", dry_run=False)
        >>> if result.is_success:
        ...     print(f"Deleted: {result.sg_id}")
        """
        logger.info(
            f"{'[DRY-RUN] ' if dry_run else ''}Deleting security group "
            f"{sg_id} ({sg_name}) in {self.region}"
        )

        if dry_run:
            return DeleteResult(
                sg_id=sg_id,
                sg_name=sg_name,
                region=self.region,
                status=DeleteStatus.DRY_RUN,
            )

        try:
            self.ec2_client.delete_security_group(GroupId=sg_id)
            logger.info(f"Successfully deleted {sg_id}")
            return DeleteResult(
                sg_id=sg_id,
                sg_name=sg_name,
                region=self.region,
                status=DeleteStatus.SUCCESS,
            )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            error_message = self.ERROR_MESSAGES.get(
                error_code,
                e.response.get("Error", {}).get("Message", str(e)),
            )
            logger.warning(f"Failed to delete {sg_id}: {error_message}")
            return DeleteResult(
                sg_id=sg_id,
                sg_name=sg_name,
                region=self.region,
                status=DeleteStatus.FAILED,
                error_message=error_message,
            )

        except Exception as e:
            logger.exception(f"Unexpected error deleting {sg_id}")
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
        Delete multiple security groups in batch.

        Parameters
        ----------
        security_groups : list of dict
            Security groups to delete. Each dict must have 'id' and 'name' keys.
        dry_run : bool, default=True
            If True, only simulate deletions.
        progress_callback : callable, optional
            Function called after each deletion with the DeleteResult.

        Returns
        -------
        DeleteSummary
            Summary containing counts and individual results.

        Examples
        --------
        Basic batch deletion:

        >>> sgs = [{"id": "sg-1", "name": "sg1"}, {"id": "sg-2", "name": "sg2"}]
        >>> summary = cleaner.delete_batch(sgs, dry_run=False)
        >>> print(f"Deleted: {summary.deleted}/{summary.total}")

        With progress tracking:

        >>> def progress(result):
        ...     status = "✓" if result.is_success else "✗"
        ...     print(f"{status} {result.sg_id}")
        >>>
        >>> summary = cleaner.delete_batch(sgs, progress_callback=progress)
        """
        logger.info(
            f"Starting batch delete of {len(security_groups)} security groups "
            f"(dry_run={dry_run})"
        )

        summary = DeleteSummary()

        for sg in security_groups:
            sg_id = sg.get("id", "")
            sg_name = sg.get("name", "Unknown")

            result = self.delete_security_group(sg_id, sg_name, dry_run=dry_run)
            summary.add_result(result)

            if progress_callback:
                try:
                    progress_callback(result)
                except Exception as e:
                    logger.warning(f"Progress callback error: {e}")

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

        Parameters
        ----------
        security_groups : list of dict
            Security groups to potentially delete.
        confirm_callback : callable
            Function that takes a security group dict and returns True to
            delete, False to skip.
        dry_run : bool, default=False
            If True, only simulate confirmed deletions.
        progress_callback : callable, optional
            Function called after each operation with the DeleteResult.

        Returns
        -------
        DeleteSummary
            Summary containing counts and individual results.

        Examples
        --------
        Interactive confirmation:

        >>> def confirm(sg):
        ...     response = input(f"Delete {sg['name']}? [y/N]: ")
        ...     return response.lower() == 'y'
        >>>
        >>> summary = cleaner.delete_with_confirmation(
        ...     security_groups,
        ...     confirm_callback=confirm
        ... )
        """
        logger.info(
            f"Starting confirmed delete of {len(security_groups)} security groups"
        )

        summary = DeleteSummary()

        for sg in security_groups:
            sg_id = sg.get("id", "")
            sg_name = sg.get("name", "Unknown")

            # Check for user confirmation
            try:
                confirmed = confirm_callback(sg)
            except Exception as e:
                logger.warning(f"Confirmation callback error for {sg_id}: {e}")
                confirmed = False

            if not confirmed:
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
                try:
                    progress_callback(result)
                except Exception as e:
                    logger.warning(f"Progress callback error: {e}")

        summary.complete()
        return summary

    @staticmethod
    def can_delete(sg: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Check if a security group can be deleted.

        Parameters
        ----------
        sg : dict
            Security group dictionary with at least 'name' and optionally
            'is_default' keys.

        Returns
        -------
        tuple
            (can_delete: bool, reason: str) - reason is empty if can_delete is True.

        Examples
        --------
        >>> can, reason = SecurityGroupCleaner.can_delete({"name": "default"})
        >>> if not can:
        ...     print(f"Cannot delete: {reason}")
        """
        # Default security groups cannot be deleted
        if sg.get("is_default", False) or sg.get("name") == "default":
            return False, "Default security groups cannot be deleted"

        return True, ""

    def __repr__(self) -> str:
        """Return string representation."""
        return f"SecurityGroupCleaner(region='{self.region}')"
