"""
AWS Client wrapper for managing boto3 connections.
"""

import boto3
from botocore.config import Config
from botocore.exceptions import (
    ClientError,
    NoCredentialsError,
    NoRegionError,
    ProfileNotFound,
)
from typing import Optional


class AWSClientError(Exception):
    """Custom exception for AWS client errors."""

    pass


class AWSClient:
    """
    Wrapper around boto3 to manage AWS connections.

    Provides client factory methods with built-in retry logic
    and error handling for various AWS services.
    """

    def __init__(
        self,
        region: str = "us-east-1",
        profile: Optional[str] = None,
        max_retries: int = 3,
        timeout: int = 30,
    ):
        """
        Initialize AWS client.

        Args:
            region: AWS region to connect to
            profile: AWS profile name from ~/.aws/credentials
            max_retries: Maximum number of retries for failed API calls
            timeout: Request timeout in seconds
        """
        self.region = region
        self.profile = profile
        self.max_retries = max_retries
        self.timeout = timeout
        self._session: Optional[boto3.Session] = None
        self._config = self._create_config()

    def _create_config(self) -> Config:
        """Create boto3 config with retry and timeout settings."""
        return Config(
            retries={"max_attempts": self.max_retries, "mode": "adaptive"},
            connect_timeout=self.timeout,
            read_timeout=self.timeout,
        )

    @property
    def session(self) -> boto3.Session:
        """
        Get or create boto3 session.

        Returns:
            boto3.Session: The AWS session

        Raises:
            AWSClientError: If session creation fails
        """
        if self._session is None:
            self._session = self._create_session()
        return self._session

    def _create_session(self) -> boto3.Session:
        """
        Create boto3 session with optional profile.

        Returns:
            boto3.Session: The created session

        Raises:
            AWSClientError: If session creation fails
        """
        try:
            if self.profile:
                return boto3.Session(
                    profile_name=self.profile, region_name=self.region
                )
            else:
                return boto3.Session(region_name=self.region)
        except ProfileNotFound:
            raise AWSClientError(
                f"AWS profile '{self.profile}' not found. "
                "Please check your ~/.aws/credentials file."
            )
        except NoRegionError:
            raise AWSClientError(
                f"Invalid or missing region: {self.region}. "
                "Please specify a valid AWS region."
            )
        except Exception as e:
            raise AWSClientError(f"Failed to create AWS session: {str(e)}")

    def _get_client(self, service_name: str):
        """
        Get a boto3 client for the specified service.

        Args:
            service_name: Name of the AWS service

        Returns:
            boto3 client for the specified service

        Raises:
            AWSClientError: If client creation fails
        """
        try:
            return self.session.client(service_name, config=self._config)
        except NoCredentialsError:
            raise AWSClientError(
                "AWS credentials not found. "
                "Please configure AWS credentials using 'aws configure' "
                "or set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables."
            )
        except Exception as e:
            raise AWSClientError(f"Failed to create {service_name} client: {str(e)}")

    def get_ec2_client(self):
        """Get EC2 client."""
        return self._get_client("ec2")

    def get_rds_client(self):
        """Get RDS client."""
        return self._get_client("rds")

    def get_elb_client(self):
        """Get Classic ELB client."""
        return self._get_client("elb")

    def get_elbv2_client(self):
        """Get Application/Network Load Balancer client."""
        return self._get_client("elbv2")

    def validate_credentials(self) -> bool:
        """
        Validate AWS credentials by making a simple API call.

        Returns:
            True if credentials are valid

        Raises:
            AWSClientError: If credentials are invalid or missing
        """
        try:
            sts = self._get_client("sts")
            identity = sts.get_caller_identity()
            return True
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            if error_code in ["InvalidClientTokenId", "SignatureDoesNotMatch"]:
                raise AWSClientError(
                    "Invalid AWS credentials. Please check your access key and secret key."
                )
            raise AWSClientError(f"Failed to validate credentials: {str(e)}")
        except Exception as e:
            raise AWSClientError(f"Failed to validate credentials: {str(e)}")

    def get_account_id(self) -> str:
        """
        Get the AWS account ID.

        Returns:
            The AWS account ID

        Raises:
            AWSClientError: If unable to get account ID
        """
        try:
            sts = self._get_client("sts")
            identity = sts.get_caller_identity()
            return identity["Account"]
        except Exception as e:
            raise AWSClientError(f"Failed to get account ID: {str(e)}")

    def with_region(self, region: str) -> "AWSClient":
        """
        Create a new AWSClient instance for a different region.

        Args:
            region: The new region

        Returns:
            A new AWSClient instance configured for the specified region
        """
        return AWSClient(
            region=region,
            profile=self.profile,
            max_retries=self.max_retries,
            timeout=self.timeout,
        )
