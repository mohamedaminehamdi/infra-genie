# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **VPC Scanner** - New module to detect unused VPCs:
  - Checks for EC2 instances, RDS, NAT Gateways, Load Balancers
  - Detects VPC-connected Lambda functions
  - Identifies ElastiCache clusters in VPC
  - Checks VPC Endpoints, Transit Gateway attachments
  - Detects VPN connections and VPC peering
  - Network interfaces in use detection
  - Option to include/exclude default VPC
- **Subnet Scanner** - New module to detect unused subnets:
  - Checks for EC2 instances deployed in subnet
  - Detects Network Interfaces (ENIs) in use
  - Identifies NAT Gateways in subnet
  - Checks Load Balancer availability zones
  - Detects Lambda functions using subnet
  - Identifies RDS and ElastiCache subnet group membership
  - Checks VPC Endpoint interfaces
  - Option to filter by VPC ID
  - Option to include/exclude default subnets
- **Elastic IP Scanner** - New module to detect unused Elastic IPs:
  - Detects EIPs not associated with any instance
  - Identifies EIPs not attached to network interfaces
  - Checks NAT Gateway EIP usage
  - Helps reduce unnecessary EIP charges
- New CLI command: `infra-genie scan vpcs`
- New CLI command: `infra-genie scan subnets`
- New CLI command: `infra-genie scan eips`
- Enterprise-grade code documentation with NumPy docstring format
- Comprehensive exception hierarchy in `src/core/exceptions.py`
- Logging configuration module in `src/core/logging.py`
- Type hints throughout the codebase
- `py.typed` marker for PEP 561 compliance
- `pyproject.toml` with full project configuration

### Changed

- Refactored all modules with detailed docstrings
- Improved error messages with actionable hints
- Enhanced CLI help text with examples
- Updated README with VPC scanner documentation

## [0.1.0] - 2024-01-15

### Added

- Initial release of Infra-Genie
- Security Group Scanner with comprehensive detection:
  - EC2 instance attachments
  - Network Interface (ENI) attachments
  - RDS instance associations
  - Classic ELB security groups
  - ALB/NLB security groups
  - Cross-references in security group rules
- Security Group Cleaner with safety features:
  - Dry-run mode
  - Interactive confirmation
  - Batch deletion
  - Progress callbacks
- Multi-region scanning with parallel execution
- Multiple output formats:
  - CLI tables with Rich formatting
  - CSV export
  - JSON export
- AWS credential management:
  - Profile support
  - Credential validation
  - Multi-region client creation
- CLI commands:
  - `scan security-groups` - Identify unused security groups
  - `delete security-groups` - Remove unused security groups
  - `regions` - List available AWS regions
  - `validate` - Verify AWS credentials

### Security

- Default VPC security groups are excluded by default
- Deletion requires explicit confirmation
- Force mode requires explicit flag

## [0.0.1] - 2024-01-01

### Added

- Project scaffolding
- Basic project structure
- Initial documentation

---

## Version History

| Version | Date | Description |
|---------|------|-------------|

| 0.1.0 | 2024-01-15 | First public release |
| 0.0.1 | 2024-01-01 | Initial development |

[Unreleased]: https://github.com/your-org/infra-genie/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/your-org/infra-genie/releases/tag/v0.1.0
[0.0.1]: https://github.com/your-org/infra-genie/releases/tag/v0.0.1
