"""
Tests for the Reporter modules.
"""

import json
import os
import tempfile
from datetime import datetime

import pytest

from src.core.base_scanner import ScanResult
from src.core.region_manager import MultiRegionScanResult
from src.reporters.cli_reporter import CLIReporter
from src.reporters.csv_reporter import CSVReporter
from src.reporters.json_reporter import JSONReporter


@pytest.fixture
def sample_scan_result():
    """Create a sample ScanResult for testing."""
    return ScanResult(
        resource_type="security_group",
        region="us-east-1",
        total_count=10,
        unused_count=3,
        unused_resources=[
            {
                "id": "sg-111111",
                "name": "unused-sg-1",
                "description": "First unused SG",
                "vpc_id": "vpc-123",
                "is_default": False,
                "tags": {"Environment": "Test"},
            },
            {
                "id": "sg-222222",
                "name": "unused-sg-2",
                "description": "Second unused SG",
                "vpc_id": "vpc-123",
                "is_default": False,
                "tags": {},
            },
            {
                "id": "sg-333333",
                "name": "unused-sg-3",
                "description": "Third unused SG",
                "vpc_id": "vpc-456",
                "is_default": False,
                "tags": {"Team": "DevOps"},
            },
        ],
        scan_time=datetime(2024, 1, 15, 10, 30, 0),
    )


@pytest.fixture
def sample_multi_region_result(sample_scan_result):
    """Create a sample MultiRegionScanResult for testing."""
    result2 = ScanResult(
        resource_type="security_group",
        region="eu-west-1",
        total_count=5,
        unused_count=1,
        unused_resources=[
            {
                "id": "sg-444444",
                "name": "eu-unused-sg",
                "description": "EU unused SG",
                "vpc_id": "vpc-789",
                "is_default": False,
                "tags": {},
            },
        ],
        scan_time=datetime(2024, 1, 15, 10, 30, 0),
    )

    return MultiRegionScanResult(
        resource_type="security_group",
        regions_scanned=["us-east-1", "eu-west-1"],
        total_resources=15,
        total_unused=4,
        results_by_region={
            "us-east-1": sample_scan_result,
            "eu-west-1": result2,
        },
        scan_time=datetime(2024, 1, 15, 10, 30, 0),
    )


class TestCSVReporter:
    """Tests for CSVReporter class."""

    def test_single_region_export(self, sample_scan_result):
        """Test exporting single region results to CSV."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False
        ) as f:
            output_path = f.name

        try:
            reporter = CSVReporter(output_path=output_path)
            result_path = reporter.report_single_region(sample_scan_result)

            assert result_path == output_path
            assert os.path.exists(output_path)

            # Read and verify content
            with open(output_path, "r") as f:
                content = f.read()
                assert "sg-111111" in content
                assert "sg-222222" in content
                assert "sg-333333" in content
                assert "us-east-1" in content
        finally:
            os.unlink(output_path)

    def test_multi_region_export(self, sample_multi_region_result):
        """Test exporting multi-region results to CSV."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False
        ) as f:
            output_path = f.name

        try:
            reporter = CSVReporter(output_path=output_path)
            result_path = reporter.report_multi_region(sample_multi_region_result)

            assert result_path == output_path

            with open(output_path, "r") as f:
                content = f.read()
                # Should have resources from both regions
                assert "us-east-1" in content
                assert "eu-west-1" in content
                assert "sg-111111" in content
                assert "sg-444444" in content
        finally:
            os.unlink(output_path)

    def test_auto_generated_filename(self, sample_scan_result):
        """Test that filename is auto-generated when not specified."""
        reporter = CSVReporter()  # No output_path
        result_path = reporter.report_single_region(sample_scan_result)

        try:
            assert result_path.endswith(".csv")
            assert "security_group" in result_path
            assert os.path.exists(result_path)
        finally:
            os.unlink(result_path)


class TestJSONReporter:
    """Tests for JSONReporter class."""

    def test_single_region_export(self, sample_scan_result):
        """Test exporting single region results to JSON."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            output_path = f.name

        try:
            reporter = JSONReporter(output_path=output_path)
            result_path = reporter.report_single_region(sample_scan_result)

            assert result_path == output_path

            with open(output_path, "r") as f:
                data = json.load(f)

            assert "metadata" in data
            assert "unused_resources" in data
            assert data["metadata"]["region"] == "us-east-1"
            assert len(data["unused_resources"]) == 3
        finally:
            os.unlink(output_path)

    def test_multi_region_export(self, sample_multi_region_result):
        """Test exporting multi-region results to JSON."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            output_path = f.name

        try:
            reporter = JSONReporter(output_path=output_path)
            result_path = reporter.report_multi_region(sample_multi_region_result)

            with open(output_path, "r") as f:
                data = json.load(f)

            assert "metadata" in data
            assert "summary_by_region" in data
            assert "unused_resources" in data
            assert "us-east-1" in data["summary_by_region"]
            assert "eu-west-1" in data["summary_by_region"]
            assert len(data["unused_resources"]) == 4
        finally:
            os.unlink(output_path)

    def test_to_string(self, sample_scan_result):
        """Test converting result to JSON string."""
        reporter = JSONReporter()
        json_str = reporter.to_string(sample_scan_result)

        data = json.loads(json_str)
        assert "metadata" in data
        assert "unused_resources" in data


class TestCLIReporter:
    """Tests for CLIReporter class."""

    def test_reporter_initialization(self):
        """Test CLI reporter initialization."""
        reporter = CLIReporter()
        assert reporter.console is not None

    def test_truncate_function(self):
        """Test text truncation."""
        reporter = CLIReporter()

        # Short text should not be truncated
        assert reporter._truncate("short", 10) == "short"

        # Long text should be truncated with ellipsis
        long_text = "This is a very long description that should be truncated"
        truncated = reporter._truncate(long_text, 20)
        assert len(truncated) == 20
        assert truncated.endswith("...")

    def test_single_region_report_no_errors(self, sample_scan_result, capsys):
        """Test single region report completes without errors."""
        reporter = CLIReporter()
        # This should complete without raising exceptions
        reporter.report_single_region(sample_scan_result)

    def test_multi_region_report_no_errors(self, sample_multi_region_result, capsys):
        """Test multi-region report completes without errors."""
        reporter = CLIReporter()
        # This should complete without raising exceptions
        reporter.report_multi_region(sample_multi_region_result)

    def test_empty_results(self):
        """Test reporting when there are no unused resources."""
        result = ScanResult(
            resource_type="security_group",
            region="us-east-1",
            total_count=10,
            unused_count=0,
            unused_resources=[],
        )

        reporter = CLIReporter()
        # Should complete without errors
        reporter.report_single_region(result)
