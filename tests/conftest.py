"""
Pytest configuration and shared fixtures for testing.
"""

import boto3
import pytest
from moto import mock_aws

from src.core.aws_client import AWSClient


@pytest.fixture
def aws_credentials():
    """Mock AWS credentials for moto."""
    import os

    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"


@pytest.fixture
def mock_aws_environment(aws_credentials):
    """Create a mocked AWS environment."""
    with mock_aws():
        yield


@pytest.fixture
def aws_client(mock_aws_environment):
    """Create an AWSClient instance for testing."""
    return AWSClient(region="us-east-1")


@pytest.fixture
def ec2_client(mock_aws_environment):
    """Create a boto3 EC2 client for setting up test resources."""
    return boto3.client("ec2", region_name="us-east-1")


@pytest.fixture
def rds_client(mock_aws_environment):
    """Create a boto3 RDS client for setting up test resources."""
    return boto3.client("rds", region_name="us-east-1")


@pytest.fixture
def elb_client(mock_aws_environment):
    """Create a boto3 ELB client for setting up test resources."""
    return boto3.client("elb", region_name="us-east-1")


@pytest.fixture
def elbv2_client(mock_aws_environment):
    """Create a boto3 ELBv2 client for setting up test resources."""
    return boto3.client("elbv2", region_name="us-east-1")


@pytest.fixture
def vpc(ec2_client):
    """Create a VPC for testing."""
    response = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = response["Vpc"]["VpcId"]
    return vpc_id


@pytest.fixture
def subnet(ec2_client, vpc):
    """Create a subnet for testing."""
    response = ec2_client.create_subnet(
        VpcId=vpc,
        CidrBlock="10.0.1.0/24",
        AvailabilityZone="us-east-1a",
    )
    return response["Subnet"]["SubnetId"]


@pytest.fixture
def security_group(ec2_client, vpc):
    """Create a security group for testing."""
    response = ec2_client.create_security_group(
        GroupName="test-sg",
        Description="Test security group",
        VpcId=vpc,
    )
    return response["GroupId"]


@pytest.fixture
def unused_security_group(ec2_client, vpc):
    """Create an unused security group for testing."""
    response = ec2_client.create_security_group(
        GroupName="unused-sg",
        Description="Unused security group for testing",
        VpcId=vpc,
    )
    return response["GroupId"]
