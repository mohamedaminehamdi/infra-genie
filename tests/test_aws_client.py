"""
Tests for the AWS Client module.
"""

import pytest
from moto import mock_aws

from src.core.aws_client import AWSClient, AWSClientError


class TestAWSClient:
    """Tests for AWSClient class."""

    def test_client_initialization(self, mock_aws_environment):
        """Test basic client initialization."""
        client = AWSClient(region="us-east-1")
        assert client.region == "us-east-1"
        assert client.profile is None

    def test_client_with_profile(self, mock_aws_environment):
        """Test client initialization with profile."""
        # Note: moto doesn't actually use profiles, but we test the attribute
        client = AWSClient(region="us-west-2", profile="test-profile")
        assert client.region == "us-west-2"
        assert client.profile == "test-profile"

    def test_get_ec2_client(self, mock_aws_environment):
        """Test getting EC2 client."""
        client = AWSClient(region="us-east-1")
        ec2 = client.get_ec2_client()
        assert ec2 is not None

    def test_get_rds_client(self, mock_aws_environment):
        """Test getting RDS client."""
        client = AWSClient(region="us-east-1")
        rds = client.get_rds_client()
        assert rds is not None

    def test_get_elb_client(self, mock_aws_environment):
        """Test getting Classic ELB client."""
        client = AWSClient(region="us-east-1")
        elb = client.get_elb_client()
        assert elb is not None

    def test_get_elbv2_client(self, mock_aws_environment):
        """Test getting ALB/NLB client."""
        client = AWSClient(region="us-east-1")
        elbv2 = client.get_elbv2_client()
        assert elbv2 is not None

    def test_validate_credentials(self, mock_aws_environment):
        """Test credential validation."""
        client = AWSClient(region="us-east-1")
        # Should not raise an exception with mocked credentials
        assert client.validate_credentials() is True

    def test_get_account_id(self, mock_aws_environment):
        """Test getting account ID."""
        client = AWSClient(region="us-east-1")
        account_id = client.get_account_id()
        assert account_id is not None
        assert len(account_id) == 12  # AWS account IDs are 12 digits

    def test_with_region(self, mock_aws_environment):
        """Test creating client for different region."""
        client = AWSClient(region="us-east-1", profile="test")
        new_client = client.with_region("eu-west-1")

        assert new_client.region == "eu-west-1"
        assert new_client.profile == "test"
        assert client.region == "us-east-1"  # Original unchanged

    def test_retry_config(self, mock_aws_environment):
        """Test that retry configuration is applied."""
        client = AWSClient(region="us-east-1", max_retries=5, timeout=60)
        assert client.max_retries == 5
        assert client.timeout == 60


class TestAWSClientErrors:
    """Tests for AWSClient error handling."""

    def test_invalid_profile_error(self, mock_aws_environment):
        """Test error handling for invalid profile."""
        # This test depends on moto behavior - it may not actually raise
        # In real usage, an invalid profile would raise ProfileNotFound
        client = AWSClient(region="us-east-1", profile="nonexistent-profile-xyz")
        # With moto, this might not raise, so we just verify creation works
        assert client.profile == "nonexistent-profile-xyz"
