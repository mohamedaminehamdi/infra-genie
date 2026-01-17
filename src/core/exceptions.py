"""
Custom Exceptions for Infra-Genie
=================================

This module defines a hierarchy of custom exceptions used throughout
the application for consistent error handling and reporting.

Exception Hierarchy
-------------------
::

    InfraGenieError (base)
    ├── AWSClientError
    │   ├── CredentialsError
    │   ├── RegionError
    │   └── ServiceError
    ├── ScannerError
    │   ├── ResourceFetchError
    │   └── ScanTimeoutError
    └── CleanerError
        ├── DeleteError
        └── DependencyError

Example
-------
>>> from src.core.exceptions import AWSClientError, CredentialsError
>>>
>>> try:
...     client.validate_credentials()
... except CredentialsError as e:
...     print(f"Invalid credentials: {e}")
... except AWSClientError as e:
...     print(f"AWS error: {e}")
"""

from __future__ import annotations

from typing import Any, Dict, Optional


class InfraGenieError(Exception):
    """
    Base exception for all Infra-Genie errors.

    All custom exceptions in the application inherit from this class,
    allowing for broad exception catching when needed.

    Parameters
    ----------
    message : str
        Human-readable error message.
    details : dict, optional
        Additional context about the error.

    Attributes
    ----------
    message : str
        The error message.
    details : dict
        Additional error details.

    Example
    -------
    >>> raise InfraGenieError("Something went wrong", details={"code": 500})
    """

    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.message = message
        self.details = details or {}
        super().__init__(self.message)

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} (Details: {self.details})"
        return self.message

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert exception to dictionary for serialization.

        Returns
        -------
        dict
            Dictionary representation of the error.
        """
        return {
            "error_type": self.__class__.__name__,
            "message": self.message,
            "details": self.details,
        }


# =============================================================================
# AWS Client Exceptions
# =============================================================================


class AWSClientError(InfraGenieError):
    """
    Base exception for AWS client-related errors.

    Raised when there's an issue with AWS connectivity, authentication,
    or service access.

    Parameters
    ----------
    message : str
        Human-readable error message.
    service : str, optional
        The AWS service that caused the error.
    region : str, optional
        The AWS region where the error occurred.
    details : dict, optional
        Additional context about the error.
    """

    def __init__(
        self,
        message: str,
        service: Optional[str] = None,
        region: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.service = service
        self.region = region
        full_details = details or {}
        if service:
            full_details["service"] = service
        if region:
            full_details["region"] = region
        super().__init__(message, full_details)


class CredentialsError(AWSClientError):
    """
    Raised when AWS credentials are invalid, missing, or expired.

    Example
    -------
    >>> raise CredentialsError(
    ...     "AWS credentials not found",
    ...     details={"hint": "Run 'aws configure' to set up credentials"}
    ... )
    """

    pass


class RegionError(AWSClientError):
    """
    Raised when there's an issue with the specified AWS region.

    Example
    -------
    >>> raise RegionError(
    ...     "Invalid region specified",
    ...     region="us-invalid-1"
    ... )
    """

    pass


class ServiceError(AWSClientError):
    """
    Raised when there's an error accessing a specific AWS service.

    Example
    -------
    >>> raise ServiceError(
    ...     "Failed to access EC2 service",
    ...     service="ec2",
    ...     region="us-east-1"
    ... )
    """

    pass


# =============================================================================
# Scanner Exceptions
# =============================================================================


class ScannerError(InfraGenieError):
    """
    Base exception for scanner-related errors.

    Raised when there's an issue during resource scanning.

    Parameters
    ----------
    message : str
        Human-readable error message.
    resource_type : str, optional
        The type of resource being scanned.
    region : str, optional
        The AWS region being scanned.
    details : dict, optional
        Additional context about the error.
    """

    def __init__(
        self,
        message: str,
        resource_type: Optional[str] = None,
        region: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.resource_type = resource_type
        self.region = region
        full_details = details or {}
        if resource_type:
            full_details["resource_type"] = resource_type
        if region:
            full_details["region"] = region
        super().__init__(message, full_details)


class ResourceFetchError(ScannerError):
    """
    Raised when unable to fetch resources from AWS.

    Example
    -------
    >>> raise ResourceFetchError(
    ...     "Failed to fetch security groups",
    ...     resource_type="security_group",
    ...     region="us-east-1"
    ... )
    """

    pass


class ScanTimeoutError(ScannerError):
    """
    Raised when a scan operation times out.

    Example
    -------
    >>> raise ScanTimeoutError(
    ...     "Scan timed out after 300 seconds",
    ...     resource_type="security_group",
    ...     details={"timeout_seconds": 300}
    ... )
    """

    pass


# =============================================================================
# Cleaner Exceptions
# =============================================================================


class CleanerError(InfraGenieError):
    """
    Base exception for cleaner-related errors.

    Raised when there's an issue during resource cleanup.

    Parameters
    ----------
    message : str
        Human-readable error message.
    resource_id : str, optional
        The ID of the resource being cleaned.
    resource_type : str, optional
        The type of resource being cleaned.
    details : dict, optional
        Additional context about the error.
    """

    def __init__(
        self,
        message: str,
        resource_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.resource_id = resource_id
        self.resource_type = resource_type
        full_details = details or {}
        if resource_id:
            full_details["resource_id"] = resource_id
        if resource_type:
            full_details["resource_type"] = resource_type
        super().__init__(message, full_details)


class DeleteError(CleanerError):
    """
    Raised when unable to delete a resource.

    Example
    -------
    >>> raise DeleteError(
    ...     "Failed to delete security group",
    ...     resource_id="sg-123456",
    ...     resource_type="security_group"
    ... )
    """

    pass


class DependencyError(CleanerError):
    """
    Raised when a resource cannot be deleted due to dependencies.

    Example
    -------
    >>> raise DependencyError(
    ...     "Security group is still in use",
    ...     resource_id="sg-123456",
    ...     details={"dependent_resources": ["eni-abc123"]}
    ... )
    """

    pass
