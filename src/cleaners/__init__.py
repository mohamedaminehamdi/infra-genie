"""
Resource Cleaners
=================

This module provides cleaner implementations for safely deleting
unused AWS resources.

Each cleaner implements safety features including:
- Dry-run mode for previewing deletions
- Interactive confirmation prompts
- Comprehensive error handling
- Progress tracking and reporting

Available Cleaners
------------------
SecurityGroupCleaner
    Deletes unused EC2 security groups.

Data Classes
------------
DeleteStatus
    Enum representing the status of a delete operation.
DeleteResult
    Result of a single resource deletion attempt.
DeleteSummary
    Summary of a batch delete operation.

Example
-------
>>> from src.cleaners import SecurityGroupCleaner, DeleteStatus
>>> from src.core import AWSClient
>>>
>>> client = AWSClient(region="us-east-1")
>>> cleaner = SecurityGroupCleaner(client)
>>>
>>> # Preview deletion (dry-run)
>>> result = cleaner.delete_security_group("sg-123", "test-sg", dry_run=True)
>>> print(f"Would delete: {result.sg_id}")
>>>
>>> # Actual deletion
>>> result = cleaner.delete_security_group("sg-123", "test-sg", dry_run=False)
>>> if result.status == DeleteStatus.SUCCESS:
...     print(f"Deleted: {result.sg_id}")

Safety Features
---------------
1. **Dry-run mode**: Preview what would be deleted without making changes
2. **Confirmation callbacks**: Require user approval before each deletion
3. **Error handling**: Graceful handling of AWS errors with user-friendly messages
4. **Progress tracking**: Callbacks for monitoring deletion progress
5. **Default SG protection**: Prevents deletion of default VPC security groups

See Also
--------
src.scanners : For identifying unused resources.
"""

from src.cleaners.security_group_cleaner import (
    DeleteResult,
    DeleteStatus,
    DeleteSummary,
    SecurityGroupCleaner,
)

__all__ = [
    "DeleteResult",
    "DeleteStatus",
    "DeleteSummary",
    "SecurityGroupCleaner",
]
