"""
Tests for the Security Group Cleaner.
"""

import pytest
from moto import mock_aws

from src.cleaners.security_group_cleaner import (
    DeleteResult,
    DeleteStatus,
    DeleteSummary,
    SecurityGroupCleaner,
)
from src.core.aws_client import AWSClient


class TestDeleteResult:
    """Tests for DeleteResult dataclass."""

    def test_create_success_result(self):
        """Test creating a success result."""
        result = DeleteResult(
            sg_id="sg-123",
            sg_name="test-sg",
            region="us-east-1",
            status=DeleteStatus.SUCCESS,
        )
        assert result.sg_id == "sg-123"
        assert result.status == DeleteStatus.SUCCESS
        assert result.error_message is None

    def test_create_failed_result(self):
        """Test creating a failed result."""
        result = DeleteResult(
            sg_id="sg-123",
            sg_name="test-sg",
            region="us-east-1",
            status=DeleteStatus.FAILED,
            error_message="Dependency violation",
        )
        assert result.status == DeleteStatus.FAILED
        assert result.error_message == "Dependency violation"

    def test_to_dict(self):
        """Test converting result to dictionary."""
        result = DeleteResult(
            sg_id="sg-123",
            sg_name="test-sg",
            region="us-east-1",
            status=DeleteStatus.SUCCESS,
        )
        data = result.to_dict()

        assert data["sg_id"] == "sg-123"
        assert data["status"] == "success"
        assert "timestamp" in data


class TestDeleteSummary:
    """Tests for DeleteSummary dataclass."""

    def test_empty_summary(self):
        """Test empty summary."""
        summary = DeleteSummary()
        assert summary.total == 0
        assert summary.deleted == 0
        assert summary.failed == 0

    def test_add_success_result(self):
        """Test adding success result updates counts."""
        summary = DeleteSummary()
        result = DeleteResult(
            sg_id="sg-123",
            sg_name="test-sg",
            region="us-east-1",
            status=DeleteStatus.SUCCESS,
        )
        summary.add_result(result)

        assert summary.total == 1
        assert summary.deleted == 1
        assert summary.failed == 0

    def test_add_failed_result(self):
        """Test adding failed result updates counts."""
        summary = DeleteSummary()
        result = DeleteResult(
            sg_id="sg-123",
            sg_name="test-sg",
            region="us-east-1",
            status=DeleteStatus.FAILED,
        )
        summary.add_result(result)

        assert summary.total == 1
        assert summary.deleted == 0
        assert summary.failed == 1

    def test_add_multiple_results(self):
        """Test adding multiple results."""
        summary = DeleteSummary()

        summary.add_result(
            DeleteResult("sg-1", "sg1", "us-east-1", DeleteStatus.SUCCESS)
        )
        summary.add_result(
            DeleteResult("sg-2", "sg2", "us-east-1", DeleteStatus.FAILED)
        )
        summary.add_result(
            DeleteResult("sg-3", "sg3", "us-east-1", DeleteStatus.SKIPPED)
        )
        summary.add_result(
            DeleteResult("sg-4", "sg4", "us-east-1", DeleteStatus.DRY_RUN)
        )

        assert summary.total == 4
        assert summary.deleted == 1
        assert summary.failed == 1
        assert summary.skipped == 1
        assert summary.dry_run == 1

    def test_complete_sets_end_time(self):
        """Test that complete() sets end_time."""
        summary = DeleteSummary()
        assert summary.end_time is None

        summary.complete()
        assert summary.end_time is not None


class TestSecurityGroupCleaner:
    """Tests for SecurityGroupCleaner class."""

    @pytest.fixture
    def cleaner(self, mock_aws_environment):
        """Create a cleaner instance."""
        client = AWSClient(region="us-east-1")
        return SecurityGroupCleaner(client)

    @pytest.fixture
    def test_security_group(self, mock_aws_environment, ec2_client, vpc):
        """Create a test security group."""
        response = ec2_client.create_security_group(
            GroupName="deletable-sg",
            Description="Security group for deletion testing",
            VpcId=vpc,
        )
        return {
            "id": response["GroupId"],
            "name": "deletable-sg",
            "description": "Security group for deletion testing",
        }

    def test_dry_run_does_not_delete(self, cleaner, test_security_group, ec2_client):
        """Test that dry run doesn't actually delete."""
        result = cleaner.delete_security_group(
            test_security_group["id"],
            test_security_group["name"],
            dry_run=True,
        )

        assert result.status == DeleteStatus.DRY_RUN

        # Verify security group still exists
        sgs = ec2_client.describe_security_groups(
            GroupIds=[test_security_group["id"]]
        )
        assert len(sgs["SecurityGroups"]) == 1

    def test_delete_security_group_success(
        self, cleaner, test_security_group, ec2_client
    ):
        """Test successful deletion of a security group."""
        result = cleaner.delete_security_group(
            test_security_group["id"],
            test_security_group["name"],
            dry_run=False,
        )

        assert result.status == DeleteStatus.SUCCESS
        assert result.error_message is None

        # Verify security group is deleted
        with pytest.raises(Exception):
            ec2_client.describe_security_groups(
                GroupIds=[test_security_group["id"]]
            )

    def test_delete_nonexistent_security_group(self, cleaner):
        """Test deleting a security group that doesn't exist."""
        result = cleaner.delete_security_group(
            "sg-nonexistent123",
            "fake-sg",
            dry_run=False,
        )

        assert result.status == DeleteStatus.FAILED
        assert result.error_message is not None

    def test_delete_batch_dry_run(self, cleaner, test_security_group):
        """Test batch deletion in dry run mode."""
        security_groups = [
            test_security_group,
            {"id": "sg-fake123", "name": "fake-sg"},
        ]

        summary = cleaner.delete_batch(security_groups, dry_run=True)

        assert summary.total == 2
        assert summary.dry_run == 2
        assert summary.deleted == 0

    def test_delete_batch_with_progress_callback(self, cleaner, test_security_group):
        """Test that progress callback is called."""
        callback_results = []

        def callback(result):
            callback_results.append(result)

        security_groups = [test_security_group]

        cleaner.delete_batch(
            security_groups,
            dry_run=True,
            progress_callback=callback,
        )

        assert len(callback_results) == 1
        assert callback_results[0].sg_id == test_security_group["id"]

    def test_delete_with_confirmation_skip(self, cleaner, test_security_group):
        """Test skipping deletion when confirmation returns False."""

        def confirm_callback(sg):
            return False  # Always skip

        summary = cleaner.delete_with_confirmation(
            [test_security_group],
            confirm_callback=confirm_callback,
            dry_run=False,
        )

        assert summary.total == 1
        assert summary.skipped == 1
        assert summary.deleted == 0

    def test_delete_with_confirmation_accept(
        self, cleaner, test_security_group, ec2_client
    ):
        """Test deletion when confirmation returns True."""

        def confirm_callback(sg):
            return True  # Always accept

        summary = cleaner.delete_with_confirmation(
            [test_security_group],
            confirm_callback=confirm_callback,
            dry_run=False,
        )

        assert summary.total == 1
        assert summary.deleted == 1

    def test_can_delete_default_sg(self):
        """Test that default security groups can't be deleted."""
        sg = {"id": "sg-123", "name": "default", "is_default": True}
        can_delete, reason = SecurityGroupCleaner.can_delete(sg)

        assert can_delete is False
        assert "Default" in reason

    def test_can_delete_regular_sg(self):
        """Test that regular security groups can be deleted."""
        sg = {"id": "sg-123", "name": "my-sg", "is_default": False}
        can_delete, reason = SecurityGroupCleaner.can_delete(sg)

        assert can_delete is True
        assert reason == ""
