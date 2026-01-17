# Infra-Genie

**Enterprise-grade AWS resource scanner and cleaner for identifying and removing unused cloud resources.**

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

---

## Overview

Infra-Genie helps organizations reduce AWS cloud costs by identifying and safely removing unused resources. Built with enterprise requirements in mind, it provides:

- **Multi-region scanning** - Scan all AWS regions in parallel
- **Modular architecture** - Easy to extend with new resource scanners
- **Safety features** - Dry-run mode, confirmations, and audit trails
- **Multiple output formats** - CLI tables, CSV, and JSON
- **Enterprise-ready** - Proper logging, error handling, and type hints

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/infra-genie.git
cd infra-genie

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"
```

### Basic Usage

```bash
# Validate AWS credentials
infra-genie validate

# Scan for unused security groups in default region
infra-genie scan security-groups

# Scan for unused VPCs
infra-genie scan vpcs

# Scan for unused subnets
infra-genie scan subnets

# Scan for unused Elastic IPs
infra-genie scan eips

# Scan all regions
infra-genie scan security-groups --all-regions
infra-genie scan vpcs --all-regions
infra-genie scan subnets --all-regions
infra-genie scan eips --all-regions

# Export results to CSV
infra-genie scan security-groups -A -o results.csv

# Preview deletion (dry-run)
infra-genie delete security-groups --dry-run

# Delete with confirmation
infra-genie delete security-groups --region us-east-1
```

## Features

### Security Group Scanner

Identifies unused security groups by checking attachments to:

| Resource Type | Detection Method |
|--------------|------------------|
| EC2 Instances | Direct SG attachment |
| Network Interfaces (ENIs) | Covers Lambda, ECS, ElastiCache, etc. |
| RDS Instances | VPC Security Groups |
| Classic Load Balancers | ELB Security Groups |
| ALB/NLB | Application/Network Load Balancers |
| Security Group Rules | Cross-references in other SGs |

### VPC Scanner

Identifies unused VPCs by checking for the absence of:

| Resource Type | Detection Method |
|--------------|------------------|
| EC2 Instances | Running or stopped instances in VPC |
| RDS Instances | Database instances in VPC subnet groups |
| NAT Gateways | Active NAT gateways |
| Load Balancers | ELB/ALB/NLB in VPC |
| Lambda Functions | VPC-connected functions |
| ElastiCache | Cache clusters in VPC |
| VPC Endpoints | Interface and gateway endpoints |
| Transit Gateway | TGW attachments |
| VPN Connections | VPN gateways attached |
| VPC Peering | Active peering connections |
| Network Interfaces | ENIs in use |

### Subnet Scanner

Identifies unused subnets by checking for the absence of:

| Resource Type | Detection Method |
|--------------|------------------|
| EC2 Instances | Instances deployed in subnet |
| Network Interfaces | ENIs in use (covers most services) |
| NAT Gateways | NAT gateways in subnet |
| Load Balancers | ELB/ALB/NLB availability zones |
| Lambda Functions | VPC-connected functions using subnet |
| RDS Subnet Groups | Subnets in DB subnet groups |
| ElastiCache Groups | Subnets in cache subnet groups |
| VPC Endpoints | Interface endpoints in subnet |

### Elastic IP Scanner

Identifies unused Elastic IPs that incur unnecessary charges:

| Status | Detection Method |
|--------|------------------|
| No Association | Not associated with any EC2 instance |
| No Network Interface | Not attached to any ENI |
| No NAT Gateway | Not used by a NAT Gateway |

**Cost Impact:** AWS charges for EIPs that are allocated but not associated with a running instance.

### Safety Features

| Feature | Description |
|---------|-------------|
| **Dry-run mode** | Preview what would be deleted without making changes |
| **Confirmation prompts** | Require user approval before deletion |
| **Default SG protection** | Never delete default VPC security groups |
| **Error recovery** | Individual failures don't stop batch operations |
| **Audit trails** | Detailed logging of all operations |

## Commands

### Scan Commands

#### Security Groups

```bash
# Scan security groups in a specific region
infra-genie scan security-groups --region eu-west-1

# Scan multiple specific regions
infra-genie scan security-groups --regions us-east-1,us-west-2,eu-west-1

# Scan all regions with a specific AWS profile
infra-genie scan security-groups --all-regions --profile production

# Export to JSON
infra-genie scan security-groups -A --format json -o results.json

# Include default VPC security groups (normally excluded)
infra-genie scan security-groups --include-default
```

#### VPCs

```bash
# Scan VPCs in a specific region
infra-genie scan vpcs --region eu-west-1

# Scan all regions
infra-genie scan vpcs --all-regions

# Include default VPC in results (normally excluded)
infra-genie scan vpcs --include-default

# Export to CSV
infra-genie scan vpcs -A -o unused-vpcs.csv

# Use specific AWS profile
infra-genie scan vpcs --all-regions --profile production
```

#### Subnets

```bash
# Scan subnets in a specific region
infra-genie scan subnets --region eu-west-1

# Scan all regions
infra-genie scan subnets --all-regions

# Filter by specific VPC
infra-genie scan subnets --vpc-id vpc-12345678

# Include default subnets in results (normally excluded)
infra-genie scan subnets --include-default

# Export to CSV
infra-genie scan subnets -A -o unused-subnets.csv

# Use specific AWS profile
infra-genie scan subnets --all-regions --profile production
```

#### Elastic IPs

```bash
# Scan Elastic IPs in a specific region
infra-genie scan eips --region eu-west-1

# Scan all regions
infra-genie scan eips --all-regions

# Export to CSV
infra-genie scan eips -A -o unused-eips.csv

# Use specific AWS profile
infra-genie scan eips --all-regions --profile production
```

### Delete Commands

```bash
# Preview deletion (recommended first step)
infra-genie delete security-groups --dry-run

# Delete with interactive confirmation
infra-genie delete security-groups --region us-east-1

# Delete across all regions
infra-genie delete security-groups --all-regions

# Auto-confirm the batch prompt (still shows summary)
infra-genie delete security-groups -A --yes

# Force mode - skip all confirmations (use with caution!)
infra-genie delete security-groups -A --force
```

### Utility Commands

```bash
# List all available AWS regions
infra-genie regions

# Validate AWS credentials
infra-genie validate --profile my-profile
```

## Configuration

### AWS Credentials

Infra-Genie supports standard AWS credential sources:

1. **Environment variables**
   ```bash
   export AWS_ACCESS_KEY_ID=your_access_key
   export AWS_SECRET_ACCESS_KEY=your_secret_key
   ```

2. **AWS credentials file** (`~/.aws/credentials`)
   ```ini
   [default]
   aws_access_key_id = your_access_key
   aws_secret_access_key = your_secret_key
   
   [production]
   aws_access_key_id = prod_access_key
   aws_secret_access_key = prod_secret_key
   ```

3. **IAM roles** (when running on AWS infrastructure)

### Required IAM Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "InfraGenieScan",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeInstances",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeRegions",
        "rds:DescribeDBInstances",
        "elasticloadbalancing:DescribeLoadBalancers",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    },
    {
      "Sid": "InfraGenieDelete",
      "Effect": "Allow",
      "Action": [
        "ec2:DeleteSecurityGroup"
      ],
      "Resource": "*"
    }
  ]
}
```

## Architecture

```
infra-genie/
├── src/
│   ├── __init__.py          # Package initialization
│   ├── main.py              # CLI entry point
│   ├── core/
│   │   ├── __init__.py
│   │   ├── aws_client.py    # AWS connection management
│   │   ├── base_scanner.py  # Abstract scanner interface
│   │   ├── region_manager.py # Multi-region orchestration
│   │   ├── exceptions.py    # Custom exception hierarchy
│   │   └── logging.py       # Logging configuration
│   ├── scanners/
│   │   ├── __init__.py
│   │   └── security_group_scanner.py
│   ├── cleaners/
│   │   ├── __init__.py
│   │   └── security_group_cleaner.py
│   └── reporters/
│       ├── __init__.py
│       ├── cli_reporter.py  # Terminal output
│       ├── csv_reporter.py  # CSV export
│       └── json_reporter.py # JSON export
├── tests/
│   ├── conftest.py
│   ├── test_aws_client.py
│   ├── test_security_group_scanner.py
│   └── test_reporters.py
├── pyproject.toml           # Project configuration
├── requirements.txt
└── README.md
```

## Development

### Setting Up Development Environment

```bash
# Install development dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install

# Run tests
pytest

# Run tests with coverage
pytest --cov=src --cov-report=html

# Run linting
ruff check src/

# Format code
black src/ tests/

# Type checking
mypy src/
```

### Adding a New Scanner

1. Create a new file in `src/scanners/`:

```python
# src/scanners/ebs_volume_scanner.py
from src.core.base_scanner import BaseScanner

class EBSVolumeScanner(BaseScanner):
    """Scanner for identifying unattached EBS volumes."""
    
    def get_resource_type(self) -> str:
        return "ebs_volume"
    
    def get_all_resources(self) -> list:
        # Implementation here
        pass
    
    def get_resources_in_use(self) -> set:
        # Implementation here
        pass
```

2. Export in `src/scanners/__init__.py`:

```python
from src.scanners.ebs_volume_scanner import EBSVolumeScanner

__all__ = ["SecurityGroupScanner", "EBSVolumeScanner"]
```

3. Add CLI command in `src/main.py`

### Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_security_group_scanner.py

# Run with verbose output
pytest -v

# Run only fast tests (skip slow integration tests)
pytest -m "not slow"
```

## Output Examples

### CLI Output

```
┌─────────────────────────────────────────────────────┐
│                                                     │
│   Security Group Scan Report                        │
│   Regions: us-east-1, us-west-2, eu-west-1          │
│                                                     │
└─────────────────────────────────────────────────────┘

  Regions Scanned:    3
  Total Resources:    45
  Unused Resources:   8
  Scan Time:          2024-01-15 10:30:00 UTC

┌──────────────┬─────────────────────┬────────────────┬────────────┐
│ Region       │ Security Group ID   │ Name           │ VPC ID     │
├──────────────┼─────────────────────┼────────────────┼────────────┤
│ us-east-1    │ sg-0abc123def456    │ old-webserver  │ vpc-123    │
│ us-east-1    │ sg-0def789ghi012    │ test-sg        │ vpc-123    │
│ us-west-2    │ sg-0jkl345mno678    │ unused-db      │ vpc-456    │
└──────────────┴─────────────────────┴────────────────┴────────────┘

Scan complete!
Results saved to: results.csv
```

### JSON Output

```json
{
  "metadata": {
    "resource_type": "security_group",
    "regions_scanned": ["us-east-1", "us-west-2"],
    "total_resources": 45,
    "unused_resources": 8,
    "scan_time": "2024-01-15T10:30:00"
  },
  "summary_by_region": {
    "us-east-1": {"total": 30, "unused": 5},
    "us-west-2": {"total": 15, "unused": 3}
  },
  "unused_resources": [
    {
      "id": "sg-0abc123def456",
      "name": "old-webserver",
      "vpc_id": "vpc-123",
      "region": "us-east-1"
    }
  ]
}
```

## Troubleshooting

### Common Issues

**Authentication errors**
```bash
# Verify credentials are configured
aws sts get-caller-identity

# Use a specific profile
infra-genie validate --profile my-profile
```

**Permission denied errors**
- Ensure your IAM user/role has the required permissions (see above)
- Check if there are SCPs or permission boundaries limiting access

**Security group deletion fails**
- The SG may still be in use (check ENIs, other SG rules)
- Run scan again to verify it's truly unused
- Check CloudTrail for recent attachments

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`pytest`)
5. Run linting (`ruff check src/`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Roadmap

- [ ] EBS Volume Scanner (unattached volumes)
- [ ] EIP Scanner (unassociated Elastic IPs)
- [ ] Lambda Scanner (unused functions)
- [ ] Snapshot Scanner (orphaned snapshots)
- [ ] Cost estimation for unused resources
- [ ] Slack/Teams notifications
- [ ] Scheduled scanning with AWS Lambda
- [ ] Web dashboard

## Support

- **Documentation**: [https://infra-genie.readthedocs.io](https://infra-genie.readthedocs.io)
- **Issues**: [GitHub Issues](https://github.com/your-org/infra-genie/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/infra-genie/discussions)

---

Made with ❤️ for the DevOps community
