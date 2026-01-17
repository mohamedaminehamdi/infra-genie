"""
AWS Client Module
=================

Provides a thread-safe wrapper around boto3 for managing AWS connections
with built-in retry logic, credential validation, and multi-region support.

This module implements the AWS client layer of the application architecture,
handling all direct communication with AWS services.

Classes
-------
AWSClient
    Main client class for AWS operations.

Example
-------
>>> from src.core.aws_client import AWSClient
>>>
>>> # Initialize client for a specific region
>>> client = AWSClient(region="us-east-1", profile="production")
>>>
>>> # Validate credentials before operations
>>> client.validate_credentials()
>>>
>>> # Get service clients
>>> ec2 = client.get_ec2_client()
>>> rds = client.get_rds_client()

Notes
-----
The client implements lazy loading for boto3 sessions and service clients
to optimize resource usage. Clients are created on first access and cached
for subsequent calls.

See Also
--------
boto3 : AWS SDK for Python
botocore : Low-level AWS client library
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import boto3
from botocore.config import Config
from botocore.exceptions import (
    ClientError,
    NoCredentialsError,
    NoRegionError,
    ProfileNotFound,
)

from src.core.exceptions import (
    AWSClientError,
    CredentialsError,
    RegionError,
    ServiceError,
)

# Module logger
logger = logging.getLogger(__name__)


class AWSClient:
    """
    Thread-safe AWS client wrapper with retry logic and credential management.

    Provides a high-level interface for AWS operations with built-in:
    - Automatic retry with exponential backoff
    - Credential validation
    - Multi-region support
    - Lazy client initialization

    Parameters
    ----------
    region : str, default="us-east-1"
        AWS region to connect to.
    profile : str, optional
        AWS profile name from ~/.aws/credentials.
    max_retries : int, default=3
        Maximum number of retries for failed API calls.
    timeout : int, default=30
        Request timeout in seconds.

    Attributes
    ----------
    region : str
        The configured AWS region.
    profile : str or None
        The configured AWS profile name.
    max_retries : int
        Maximum retry attempts for API calls.
    timeout : int
        Request timeout in seconds.

    Examples
    --------
    Basic usage with default credentials:

    >>> client = AWSClient(region="us-east-1")
    >>> client.validate_credentials()
    True

    Using a named profile:

    >>> client = AWSClient(region="eu-west-1", profile="production")
    >>> account_id = client.get_account_id()
    >>> print(f"Connected to account: {account_id}")

    Creating a client for a different region:

    >>> us_client = AWSClient(region="us-east-1")
    >>> eu_client = us_client.with_region("eu-west-1")

    Raises
    ------
    CredentialsError
        If AWS credentials are not found or invalid.
    RegionError
        If the specified region is invalid.
    ServiceError
        If unable to connect to an AWS service.

    See Also
    --------
    RegionManager : For multi-region operations.
    """

    # Supported AWS services and their client names
    SUPPORTED_SERVICES = {
        "ec2": "Amazon EC2",
        "rds": "Amazon RDS",
        "elb": "Elastic Load Balancing (Classic)",
        "elbv2": "Elastic Load Balancing (v2)",
        "sts": "AWS Security Token Service",
        "lambda": "AWS Lambda",
        "elasticache": "Amazon ElastiCache",
    }

    def __init__(
        self,
        region: str = "us-east-1",
        profile: Optional[str] = None,
        max_retries: int = 3,
        timeout: int = 30,
    ) -> None:
        """Initialize AWS client with the specified configuration."""
        self.region = region
        self.profile = profile
        self.max_retries = max_retries
        self.timeout = timeout

        # Lazy-loaded components
        self._session: Optional[boto3.Session] = None
        self._clients: dict[str, Any] = {}

        # Pre-create config (lightweight operation)
        self._config = self._create_config()

        logger.debug(
            "Initialized AWSClient",
            extra={"region": region, "profile": profile},
        )

    def _create_config(self) -> Config:
        """
        Create boto3 configuration with retry and timeout settings.

        Returns
        -------
        Config
            Boto3 configuration object.

        Notes
        -----
        Uses adaptive retry mode which dynamically adjusts retry behavior
        based on the error type and retry count.
        """
        return Config(
            retries={
                "max_attempts": self.max_retries,
                "mode": "adaptive",
            },
            connect_timeout=self.timeout,
            read_timeout=self.timeout,
        )

    @property
    def session(self) -> boto3.Session:
        """
        Get or create the boto3 session (lazy initialization).

        Returns
        -------
        boto3.Session
            The configured AWS session.

        Raises
        ------
        CredentialsError
            If credentials are not found.
        RegionError
            If the region is invalid.
        """
        if self._session is None:
            self._session = self._create_session()
        return self._session

    def _create_session(self) -> boto3.Session:
        """
        Create a new boto3 session with the configured profile and region.

        Returns
        -------
        boto3.Session
            The created session.

        Raises
        ------
        CredentialsError
            If the specified profile is not found.
        RegionError
            If the region is invalid or missing.
        AWSClientError
            For other session creation failures.
        """
        try:
            session_kwargs = {"region_name": self.region}
            if self.profile:
                session_kwargs["profile_name"] = self.profile

            session = boto3.Session(**session_kwargs)
            logger.debug(f"Created boto3 session for region {self.region}")
            return session

        except ProfileNotFound:
            raise CredentialsError(
                f"AWS profile '{self.profile}' not found",
                details={
                    "profile": self.profile,
                    "hint": "Check ~/.aws/credentials for available profiles",
                },
            )
        except NoRegionError:
            raise RegionError(
                f"Invalid or missing region: {self.region}",
                region=self.region,
                details={"hint": "Specify a valid AWS region like 'us-east-1'"},
            )
        except Exception as e:
            logger.exception("Failed to create AWS session")
            raise AWSClientError(
                f"Failed to create AWS session: {e}",
                region=self.region,
            )

    def _get_client(self, service_name: str) -> Any:
        """
        Get or create a boto3 client for the specified service.

        Implements client caching to avoid creating multiple clients
        for the same service.

        Parameters
        ----------
        service_name : str
            Name of the AWS service (e.g., 'ec2', 'rds').

        Returns
        -------
        botocore.client.BaseClient
            The boto3 client for the specified service.

        Raises
        ------
        CredentialsError
            If credentials are not found.
        ServiceError
            If unable to create the client.
        """
        if service_name in self._clients:
            return self._clients[service_name]

        try:
            client = self.session.client(service_name, config=self._config)
            self._clients[service_name] = client
            logger.debug(f"Created {service_name} client for {self.region}")
            return client

        except NoCredentialsError:
            raise CredentialsError(
                "AWS credentials not found",
                details={
                    "hint": (
                        "Configure credentials using 'aws configure' or set "
                        "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables"
                    ),
                },
            )
        except Exception as e:
            logger.exception(f"Failed to create {service_name} client")
            raise ServiceError(
                f"Failed to create {service_name} client: {e}",
                service=service_name,
                region=self.region,
            )

    # =========================================================================
    # Service Client Accessors
    # =========================================================================

    def get_ec2_client(self) -> Any:
        """
        Get the EC2 client.

        Returns
        -------
        EC2.Client
            Boto3 EC2 client.

        Example
        -------
        >>> ec2 = client.get_ec2_client()
        >>> response = ec2.describe_security_groups()
        """
        return self._get_client("ec2")

    def get_rds_client(self) -> Any:
        """
        Get the RDS client.

        Returns
        -------
        RDS.Client
            Boto3 RDS client.

        Example
        -------
        >>> rds = client.get_rds_client()
        >>> response = rds.describe_db_instances()
        """
        return self._get_client("rds")

    def get_elb_client(self) -> Any:
        """
        Get the Classic Elastic Load Balancing client.

        Returns
        -------
        ELB.Client
            Boto3 ELB client for Classic Load Balancers.

        Example
        -------
        >>> elb = client.get_elb_client()
        >>> response = elb.describe_load_balancers()
        """
        return self._get_client("elb")

    def get_elbv2_client(self) -> Any:
        """
        Get the Elastic Load Balancing v2 client (ALB/NLB).

        Returns
        -------
        ELBv2.Client
            Boto3 ELBv2 client for Application and Network Load Balancers.

        Example
        -------
        >>> elbv2 = client.get_elbv2_client()
        >>> response = elbv2.describe_load_balancers()
        """
        return self._get_client("elbv2")

    def get_lambda_client(self) -> Any:
        """
        Get the Lambda client.

        Returns
        -------
        Lambda.Client
            Boto3 Lambda client.

        Example
        -------
        >>> lambda_client = client.get_lambda_client()
        >>> response = lambda_client.list_functions()
        """
        return self._get_client("lambda")

    def get_elasticache_client(self) -> Any:
        """
        Get the ElastiCache client.

        Returns
        -------
        ElastiCache.Client
            Boto3 ElastiCache client.

        Example
        -------
        >>> elasticache = client.get_elasticache_client()
        >>> response = elasticache.describe_cache_clusters()
        """
        return self._get_client("elasticache")

    # =========================================================================
    # Credential and Account Operations
    # =========================================================================

    def validate_credentials(self) -> bool:
        """
        Validate AWS credentials by calling STS GetCallerIdentity.

        Returns
        -------
        bool
            True if credentials are valid.

        Raises
        ------
        CredentialsError
            If credentials are invalid, expired, or missing.

        Example
        -------
        >>> client = AWSClient()
        >>> if client.validate_credentials():
        ...     print("Credentials are valid!")
        """
        try:
            sts = self._get_client("sts")
            identity = sts.get_caller_identity()
            logger.info(
                "Credentials validated",
                extra={
                    "account": identity["Account"],
                    "arn": identity["Arn"],
                },
            )
            return True

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            if error_code in ("InvalidClientTokenId", "SignatureDoesNotMatch"):
                raise CredentialsError(
                    "Invalid AWS credentials",
                    details={
                        "error_code": error_code,
                        "hint": "Check your access key and secret key",
                    },
                )
            raise CredentialsError(f"Failed to validate credentials: {e}")

        except Exception as e:
            logger.exception("Credential validation failed")
            raise CredentialsError(f"Failed to validate credentials: {e}")

    def get_account_id(self) -> str:
        """
        Get the AWS account ID for the current credentials.

        Returns
        -------
        str
            The 12-digit AWS account ID.

        Raises
        ------
        AWSClientError
            If unable to retrieve the account ID.

        Example
        -------
        >>> client = AWSClient()
        >>> account_id = client.get_account_id()
        >>> print(f"Account: {account_id}")
        '123456789012'
        """
        try:
            sts = self._get_client("sts")
            identity = sts.get_caller_identity()
            return identity["Account"]
        except Exception as e:
            logger.exception("Failed to get account ID")
            raise AWSClientError(f"Failed to get account ID: {e}")

    def get_caller_identity(self) -> dict[str, str]:
        """
        Get full caller identity information.

        Returns
        -------
        dict
            Dictionary containing 'Account', 'Arn', and 'UserId'.

        Example
        -------
        >>> identity = client.get_caller_identity()
        >>> print(f"ARN: {identity['Arn']}")
        """
        try:
            sts = self._get_client("sts")
            return sts.get_caller_identity()
        except Exception as e:
            logger.exception("Failed to get caller identity")
            raise AWSClientError(f"Failed to get caller identity: {e}")

    # =========================================================================
    # Factory Methods
    # =========================================================================

    def with_region(self, region: str) -> AWSClient:
        """
        Create a new AWSClient instance for a different region.

        Parameters
        ----------
        region : str
            The AWS region for the new client.

        Returns
        -------
        AWSClient
            A new client instance configured for the specified region.

        Notes
        -----
        The new client inherits all other settings (profile, retries, timeout)
        from the current client.

        Example
        -------
        >>> us_client = AWSClient(region="us-east-1")
        >>> eu_client = us_client.with_region("eu-west-1")
        >>> print(eu_client.region)
        'eu-west-1'
        """
        return AWSClient(
            region=region,
            profile=self.profile,
            max_retries=self.max_retries,
            timeout=self.timeout,
        )

    # =========================================================================
    # Context Manager Support
    # =========================================================================

    def __enter__(self) -> AWSClient:
        """Enter context manager."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit context manager and cleanup resources."""
        self._clients.clear()
        self._session = None

    # =========================================================================
    # String Representation
    # =========================================================================

    def __repr__(self) -> str:
        """Return string representation of the client."""
        return (
            f"AWSClient(region='{self.region}', "
            f"profile={self.profile!r}, "
            f"max_retries={self.max_retries})"
        )


# =============================================================================
# Backward Compatibility
# =============================================================================

# Re-export AWSClientError from exceptions module for backward compatibility
# This allows: from src.core.aws_client import AWSClientError
__all__ = ["AWSClient", "AWSClientError"]
