"""
Tests for the Region Manager module.
"""

import pytest
from moto import mock_aws

from src.core.region_manager import RegionManager, MultiRegionScanResult
from src.scanners.security_group_scanner import SecurityGroupScanner


class TestRegionManager:
    """Tests for RegionManager class."""

    def test_initialization(self, mock_aws_environment):
        """Test basic initialization."""
        manager = RegionManager()
        assert manager.profile is None
        assert manager.max_workers == 10

    def test_initialization_with_options(self, mock_aws_environment):
        """Test initialization with custom options."""
        manager = RegionManager(
            profile="test",
            max_workers=5,
            max_retries=5,
            timeout=60,
        )
        assert manager.profile == "test"
        assert manager.max_workers == 5
        assert manager.max_retries == 5
        assert manager.timeout == 60

    def test_get_all_regions(self, mock_aws_environment):
        """Test fetching all AWS regions."""
        manager = RegionManager()
        regions = manager.get_all_regions()

        assert isinstance(regions, list)
        assert len(regions) > 0
        assert "us-east-1" in regions

    def test_get_client_for_region(self, mock_aws_environment):
        """Test getting client for specific region."""
        manager = RegionManager()
        client = manager.get_client_for_region("eu-west-1")

        assert client.region == "eu-west-1"

    def test_scan_single_region(self, mock_aws_environment, ec2_client, vpc):
        """Test scanning a single region."""
        # Create an unused security group
        ec2_client.create_security_group(
            GroupName="test-sg",
            Description="Test SG",
            VpcId=vpc,
        )

        manager = RegionManager()
        result = manager.scan_single_region(SecurityGroupScanner, "us-east-1")

        assert result.region == "us-east-1"
        assert result.resource_type == "security_group"
        assert result.total_count >= 1

    def test_scan_multiple_regions(self, mock_aws_environment):
        """Test scanning multiple regions."""
        manager = RegionManager(max_workers=2)

        # Scan just 2 regions for speed
        regions = ["us-east-1", "us-west-2"]
        result = manager.scan_regions(SecurityGroupScanner, regions=regions)

        assert isinstance(result, MultiRegionScanResult)
        assert result.resource_type == "security_group"
        assert len(result.regions_scanned) == 2
        assert "us-east-1" in result.regions_scanned
        assert "us-west-2" in result.regions_scanned


class TestMultiRegionScanResult:
    """Tests for MultiRegionScanResult class."""

    def test_get_all_unused_resources(self, mock_aws_environment):
        """Test aggregating unused resources from all regions."""
        manager = RegionManager(max_workers=2)
        regions = ["us-east-1", "us-west-2"]
        result = manager.scan_regions(SecurityGroupScanner, regions=regions)

        all_unused = result.get_all_unused_resources()
        assert isinstance(all_unused, list)

        # Each resource should have a region field
        for resource in all_unused:
            assert "region" in resource

    def test_to_dict(self, mock_aws_environment):
        """Test converting result to dictionary."""
        manager = RegionManager(max_workers=2)
        regions = ["us-east-1"]
        result = manager.scan_regions(SecurityGroupScanner, regions=regions)

        result_dict = result.to_dict()

        assert "resource_type" in result_dict
        assert "regions_scanned" in result_dict
        assert "total_resources" in result_dict
        assert "total_unused" in result_dict
        assert "results_by_region" in result_dict
        assert "scan_time" in result_dict

    def test_progress_callback(self, mock_aws_environment):
        """Test progress callback is called."""
        manager = RegionManager(max_workers=1)

        callback_calls = []

        def progress_callback(region, status):
            callback_calls.append((region, status))

        regions = ["us-east-1"]
        manager.scan_regions(
            SecurityGroupScanner,
            regions=regions,
            progress_callback=progress_callback,
        )

        # Should have been called at least once
        assert len(callback_calls) > 0
        # Should have complete status
        assert any(status == "complete" for _, status in callback_calls)
