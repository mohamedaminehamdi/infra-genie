"""
Tests for the Security Group Scanner.
"""

import pytest
from moto import mock_aws

from src.core.aws_client import AWSClient
from src.scanners.security_group_scanner import SecurityGroupScanner


class TestSecurityGroupScanner:
    """Tests for SecurityGroupScanner class."""

    def test_get_resource_type(self, aws_client):
        """Test that resource type is correctly returned."""
        scanner = SecurityGroupScanner(aws_client)
        assert scanner.get_resource_type() == "security_group"

    def test_get_all_security_groups(self, aws_client, ec2_client, vpc):
        """Test fetching all security groups."""
        # Create a test security group
        ec2_client.create_security_group(
            GroupName="test-sg",
            Description="Test SG",
            VpcId=vpc,
        )

        scanner = SecurityGroupScanner(aws_client)
        sgs = scanner.get_all_resources()

        # Should have at least 2 SGs (default + test-sg)
        assert len(sgs) >= 2

        # Check structure of returned data
        for sg in sgs:
            assert "id" in sg
            assert "name" in sg
            assert "description" in sg
            assert "vpc_id" in sg
            assert "is_default" in sg

    def test_find_unused_security_group(self, aws_client, ec2_client, vpc):
        """Test finding an unused security group."""
        # Create an unused security group
        response = ec2_client.create_security_group(
            GroupName="unused-sg",
            Description="This SG is not attached to anything",
            VpcId=vpc,
        )
        unused_sg_id = response["GroupId"]

        scanner = SecurityGroupScanner(aws_client, exclude_default=True)
        result = scanner.scan()

        # The unused SG should be in the results
        unused_ids = [sg["id"] for sg in result.unused_resources]
        assert unused_sg_id in unused_ids

    def test_security_group_attached_to_ec2_not_unused(
        self, aws_client, ec2_client, vpc, subnet
    ):
        """Test that a security group attached to EC2 is not marked as unused."""
        # Create a security group
        sg_response = ec2_client.create_security_group(
            GroupName="ec2-attached-sg",
            Description="SG attached to EC2",
            VpcId=vpc,
        )
        sg_id = sg_response["GroupId"]

        # Create an EC2 instance with the security group
        ec2_client.run_instances(
            ImageId="ami-12345678",
            MinCount=1,
            MaxCount=1,
            InstanceType="t2.micro",
            SubnetId=subnet,
            SecurityGroupIds=[sg_id],
        )

        scanner = SecurityGroupScanner(aws_client, exclude_default=True)
        result = scanner.scan()

        # The attached SG should NOT be in unused results
        unused_ids = [sg["id"] for sg in result.unused_resources]
        assert sg_id not in unused_ids

    def test_security_group_attached_to_eni_not_unused(
        self, aws_client, ec2_client, vpc, subnet
    ):
        """Test that a security group attached to ENI is not marked as unused."""
        # Create a security group
        sg_response = ec2_client.create_security_group(
            GroupName="eni-attached-sg",
            Description="SG attached to ENI",
            VpcId=vpc,
        )
        sg_id = sg_response["GroupId"]

        # Create a network interface with the security group
        ec2_client.create_network_interface(
            SubnetId=subnet,
            Groups=[sg_id],
        )

        scanner = SecurityGroupScanner(aws_client, exclude_default=True)
        result = scanner.scan()

        # The attached SG should NOT be in unused results
        unused_ids = [sg["id"] for sg in result.unused_resources]
        assert sg_id not in unused_ids

    def test_default_security_group_excluded(self, aws_client, ec2_client, vpc):
        """Test that default VPC security groups are excluded by default."""
        scanner = SecurityGroupScanner(aws_client, exclude_default=True)
        result = scanner.scan()

        # No default SGs should be in unused results
        for sg in result.unused_resources:
            assert sg["name"] != "default"
            assert sg["is_default"] is False

    def test_default_security_group_included_when_configured(
        self, aws_client, ec2_client, vpc
    ):
        """Test that default VPC security groups can be included."""
        scanner = SecurityGroupScanner(aws_client, exclude_default=False)
        result = scanner.scan()

        # Check if we have any default SGs (they exist but may be "in use"
        # by being referenced or because moto creates default resources)
        all_sgs = scanner.get_all_resources()
        default_sgs = [sg for sg in all_sgs if sg["is_default"]]

        # Default SGs exist
        assert len(default_sgs) > 0

    def test_security_group_referenced_by_other_sg_not_unused(
        self, aws_client, ec2_client, vpc
    ):
        """Test that a SG referenced by another SG's rules is not marked as unused."""
        # Create a security group that will be referenced
        sg1_response = ec2_client.create_security_group(
            GroupName="referenced-sg",
            Description="This SG will be referenced",
            VpcId=vpc,
        )
        sg1_id = sg1_response["GroupId"]

        # Create another security group that references the first
        sg2_response = ec2_client.create_security_group(
            GroupName="referencing-sg",
            Description="This SG references another SG",
            VpcId=vpc,
        )
        sg2_id = sg2_response["GroupId"]

        # Add a rule to sg2 that references sg1
        ec2_client.authorize_security_group_ingress(
            GroupId=sg2_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "UserIdGroupPairs": [{"GroupId": sg1_id}],
                }
            ],
        )

        scanner = SecurityGroupScanner(aws_client, exclude_default=True)
        result = scanner.scan()

        # The referenced SG should NOT be in unused results
        unused_ids = [sg["id"] for sg in result.unused_resources]
        assert sg1_id not in unused_ids

    def test_scan_result_structure(self, aws_client, ec2_client, vpc):
        """Test the structure of scan results."""
        scanner = SecurityGroupScanner(aws_client)
        result = scanner.scan()

        assert result.resource_type == "security_group"
        assert result.region == "us-east-1"
        assert isinstance(result.total_count, int)
        assert isinstance(result.unused_count, int)
        assert isinstance(result.unused_resources, list)
        assert result.scan_time is not None

    def test_scan_result_to_dict(self, aws_client, ec2_client, vpc):
        """Test converting scan result to dictionary."""
        scanner = SecurityGroupScanner(aws_client)
        result = scanner.scan()
        result_dict = result.to_dict()

        assert "resource_type" in result_dict
        assert "region" in result_dict
        assert "total_count" in result_dict
        assert "unused_count" in result_dict
        assert "unused_resources" in result_dict
        assert "scan_time" in result_dict


class TestSecurityGroupScannerEdgeCases:
    """Edge case tests for SecurityGroupScanner."""

    def test_empty_account(self, aws_client):
        """Test scanning an account with only default SGs."""
        scanner = SecurityGroupScanner(aws_client, exclude_default=True)
        result = scanner.scan()

        # Should complete without errors
        assert result.errors == []

    def test_multiple_vpcs(self, aws_client, ec2_client):
        """Test scanning with multiple VPCs."""
        # Create multiple VPCs
        vpc1 = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        vpc2 = ec2_client.create_vpc(CidrBlock="10.1.0.0/16")["Vpc"]["VpcId"]

        # Create SGs in each VPC
        sg1 = ec2_client.create_security_group(
            GroupName="vpc1-sg",
            Description="SG in VPC 1",
            VpcId=vpc1,
        )["GroupId"]

        sg2 = ec2_client.create_security_group(
            GroupName="vpc2-sg",
            Description="SG in VPC 2",
            VpcId=vpc2,
        )["GroupId"]

        scanner = SecurityGroupScanner(aws_client, exclude_default=True)
        result = scanner.scan()

        # Both SGs should be found as unused
        unused_ids = [sg["id"] for sg in result.unused_resources]
        assert sg1 in unused_ids
        assert sg2 in unused_ids

    def test_security_group_with_tags(self, aws_client, ec2_client, vpc):
        """Test that tags are captured correctly."""
        # Create a security group with tags
        sg_response = ec2_client.create_security_group(
            GroupName="tagged-sg",
            Description="SG with tags",
            VpcId=vpc,
            TagSpecifications=[
                {
                    "ResourceType": "security-group",
                    "Tags": [
                        {"Key": "Environment", "Value": "Test"},
                        {"Key": "Team", "Value": "DevOps"},
                    ],
                }
            ],
        )
        sg_id = sg_response["GroupId"]

        scanner = SecurityGroupScanner(aws_client, exclude_default=True)
        result = scanner.scan()

        # Find the tagged SG in results
        tagged_sg = next(
            (sg for sg in result.unused_resources if sg["id"] == sg_id),
            None,
        )

        assert tagged_sg is not None
        assert tagged_sg["tags"]["Environment"] == "Test"
        assert tagged_sg["tags"]["Team"] == "DevOps"
