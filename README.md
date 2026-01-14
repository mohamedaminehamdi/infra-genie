# Infra-Genie

**AWS Resource Scanner** - Find unused resources across your AWS account to reduce cloud costs.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Validate AWS credentials
python -m src.main validate

# Scan for unused security groups in default region (us-east-1)
python -m src.main scan security-groups

# Scan ALL regions
python -m src.main scan security-groups --all-regions

# Export results to CSV
python -m src.main scan security-groups --all-regions --output results.csv

# Export results to JSON
python -m src.main scan security-groups --all-regions --format json --output results.json
```

## Features

- **Multi-region scanning** - Scan all AWS regions in parallel
- **Security Group Scanner** - Find unused security groups not attached to any resource
- **Delete Command** - Safely delete unused resources with dry-run mode and confirmations
- **Multiple output formats** - CLI tables, CSV, and JSON
- **AWS Profile support** - Use named profiles from ~/.aws/credentials
- **Modular architecture** - Easily extensible for new resource types

## Delete Unused Resources

```bash
# Preview what would be deleted (safe - no actual deletion)
python -m src.main delete security-groups --dry-run

# Delete with confirmation prompt
python -m src.main delete security-groups --region us-east-1

# Delete across all regions
python -m src.main delete security-groups --all-regions

# Auto-confirm batch deletion
python -m src.main delete security-groups --all-regions --yes

# Skip all confirmations (dangerous!)
python -m src.main delete security-groups --all-regions --force
```

### Safety Features

| Flag | Description |
|------|-------------|
| `--dry-run` | Preview what would be deleted without actually deleting |
| (default) | Asks for confirmation before deleting |
| `--yes` | Auto-confirm the batch deletion prompt |
| `--force` | Skip ALL confirmations (use with extreme caution) |

## Project Overview

A tool that scans AWS accounts to identify and report unused/idle resources across all services, helping teams reduce cloud costs by eliminating waste. The tool provides actionable reports that engineers can review before cleaning up resources.

## Problem Statement

AWS accounts accumulate unused resources over time (orphaned security groups, unattached EBS volumes, idle load balancers, etc.) that continue to incur costs. Manual identification is time-consuming and error-prone across multiple regions and services.

## Solution

An automated scanner that:
- Connects to AWS account(s) via IAM credentials
- Scans all regions for specified resource types
- Identifies unused/orphaned resources based on defined rules
- Generates reports (CLI output, CSV, JSON)

## Technical Architecture

### Core Components

1. **AWS Client Layer**
   - Uses boto3 (Python) or AWS SDK (Go/Node.js)
   - Handles authentication via IAM credentials/roles
   - Supports multi-region scanning
   - Implements rate limiting and retry logic

2. **Scanner Engine**
   - Modular design - each resource type has its own scanner module
   - Rule-based detection (configurable rules per resource type)
   - Parallel execution for performance (scan multiple regions concurrently)
   - Caching to avoid redundant API calls

3. **Resource Detectors**
   - Security Groups: Find SGs not attached to any ENI, EC2, RDS, Lambda, etc.
   - EBS Volumes: Find available (unattached) volumes
   - Elastic IPs: Find EIPs not associated with running instances
   - Load Balancers: Find ELBs/ALBs with no healthy targets
   - RDS Instances: Find stopped instances idle for X days
   - Lambda Functions: Find functions not invoked in X days
   - EC2 Instances: Find stopped instances idle for X days
   - Snapshots: Find snapshots of non-existent volumes
   - AMIs: Find AMIs not used by any instance
   - VPCs: Find VPCs with no resources
   - NAT Gateways: Find NAT gateways with no traffic

4. **Reporting Engine**
   - CLI output (table format)
   - JSON export
   - CSV export
   - HTML report with charts
   - Integration with Slack/email for notifications

5. **Configuration**
   - YAML/JSON config file for:
     - AWS credentials/profile
     - Regions to scan (or all)
     - Resource types to scan
     - Rules per resource type (e.g., "unused if no activity for 30 days")
     - Whitelists (tags, names, IDs to ignore)
     - Output format preferences

### Technology Stack Options

**Option 1: Python**
- boto3 for AWS SDK
- pandas for data manipulation
- click/typer for CLI
- pytest for testing
- Fast development, rich ecosystem

**Option 2: Go**
- AWS SDK for Go
- Cobra for CLI
- Fast execution, single binary distribution
- Better for large-scale deployments

**Option 3: Node.js/TypeScript**
- AWS SDK for JavaScript
- Commander.js for CLI
- Good for teams already using Node

**Recommendation**: Start with **Python** for rapid MVP development, can port to Go later if performance is critical.

### Data Flow

```
[User Config] → [AWS Client] → [Scanner Engine]
                                      ↓
                [Resource Detectors (parallel)]
                                      ↓
                [Aggregation & Filtering]
                                      ↓
                [Reporting Engine] → [Output (CLI/CSV/JSON)]
```

### IAM Permissions Required

Minimum read-only permissions needed:
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "ec2:Describe*",
      "elasticloadbalancing:Describe*",
      "rds:Describe*",
      "lambda:List*",
      "lambda:GetFunction",
      "s3:ListAllMyBuckets",
      "s3:GetBucketLocation",
      "cloudwatch:GetMetricStatistics"
    ],
    "Resource": "*"
  }]
}
```

---

## MVP Specification

### Goal
Build the **smallest functional version** that provides immediate value: scan all security groups in an AWS account and identify which ones are unused.

### MVP Scope

**IN SCOPE:**
- Scan a single AWS account
- Single region (configurable, default to us-east-1)
- One resource type: Security Groups
- Detection rule: Security group is "unused" if:
  - Not attached to any EC2 instance
  - Not attached to any ENI (Elastic Network Interface)
  - Not attached to any RDS instance
  - Not attached to any Load Balancer
  - Not referenced by any other security group
- Output: Simple CLI table showing unused security groups
- Output: CSV export

**OUT OF SCOPE (for MVP):**
- Multi-region support
- Other resource types (EBS, EIP, etc.)
- Web UI
- Auto-deletion features
- Historical tracking
- Multi-account support
- Advanced filtering/whitelisting

### MVP User Stories

1. As a DevOps engineer, I want to run a single command that shows me all unused security groups in my AWS account
2. As a DevOps engineer, I want to export the results to CSV so I can share with my team
3. As a DevOps engineer, I want to see which region was scanned and when

### MVP Technical Implementation

**File Structure:**
```
aws-resource-cleaner/
├── README.md
├── requirements.txt
├── config.example.yml
├── .gitignore
├── src/
│   ├── __init__.py
│   ├── main.py                 # CLI entry point
│   ├── aws_client.py           # AWS connection handling
│   ├── scanners/
│   │   ├── __init__.py
│   │   └── security_group_scanner.py
│   └── reporters/
│       ├── __init__.py
│       ├── cli_reporter.py
│       └── csv_reporter.py
└── tests/
    └── test_security_group_scanner.py
```

**Core Classes:**

```python
# aws_client.py
class AWSClient:
    def __init__(self, region='us-east-1', profile=None):
        # Initialize boto3 client
        pass
    
    def get_ec2_client(self):
        # Return EC2 client
        pass

# scanners/security_group_scanner.py
class SecurityGroupScanner:
    def __init__(self, aws_client):
        self.client = aws_client
    
    def scan(self):
        # Get all security groups
        # Get all ENIs and their security groups
        # Get all EC2 instances and their security groups
        # Get all RDS instances and their security groups
        # Get all load balancers and their security groups
        # Compare and find unused
        return unused_security_groups
    
    def _get_all_security_groups(self):
        pass
    
    def _get_security_groups_in_use(self):
        pass
    
    def _find_unused(self, all_sgs, used_sgs):
        pass

# reporters/cli_reporter.py
class CLIReporter:
    def report(self, unused_resources):
        # Print table to console
        pass

# reporters/csv_reporter.py
class CSVReporter:
    def report(self, unused_resources, filename):
        # Export to CSV
        pass
```

**CLI Interface:**
```bash
# Basic usage
$ python -m src.main scan security-groups

# Specify region
$ python -m src.main scan security-groups --region us-west-2

# Export to CSV
$ python -m src.main scan security-groups --output unused_sgs.csv

# Use specific AWS profile
$ python -m src.main scan security-groups --profile production
```

**Expected Output:**
```
Scanning security groups in us-east-1...

Found 45 total security groups
Found 12 unused security groups

┌─────────────────────┬──────────────────────┬─────────────────────────────────┐
│ Security Group ID   │ Name                 │ Description                     │
├─────────────────────┼──────────────────────┼─────────────────────────────────┤
│ sg-0123456789abcdef │ old-web-server-sg    │ Old web server security group   │
│ sg-0987654321fedcba │ test-sg-2023         │ Test security group             │
│ ...                 │ ...                  │ ...                             │
└─────────────────────┴──────────────────────┴─────────────────────────────────┘

Report saved to: unused_security_groups_2024-02-05.csv
```

### MVP Development Phases

**Phase 1: Setup & AWS Connection (Day 1)**
- Set up Python project structure
- Install boto3
- Implement AWSClient class
- Test connection to AWS
- Add basic error handling

**Phase 2: Security Group Scanner (Day 2-3)**
- Implement SecurityGroupScanner
- Fetch all security groups in region
- Fetch all resources that use security groups:
  - EC2 instances
  - Network interfaces (ENIs)
  - RDS instances
  - Load balancers (ELB, ALB, NLB)
- Cross-reference to find unused SGs
- Add unit tests

**Phase 3: Reporting (Day 4)**
- Implement CLI table output (use prettytable or rich library)
- Implement CSV export
- Add timestamp and metadata to reports

**Phase 4: CLI & Polish (Day 5)**
- Build CLI with argparse or click
- Add command-line arguments (region, profile, output)
- Error handling and user-friendly messages
- README documentation
- Usage examples

### MVP Success Criteria

- ✅ Can scan a single AWS region for unused security groups
- ✅ Accurately identifies security groups with no attachments
- ✅ Outputs results in CLI table format
- ✅ Exports results to CSV
- ✅ Completes scan in under 60 seconds for accounts with <500 security groups
- ✅ Has basic error handling (credentials, network, API limits)
- ✅ Has README with setup and usage instructions

---

## MVP+1: Next Features After MVP

Once MVP is validated, add these features in order of priority:

1. **Multi-region support** - Scan all regions or specified list of regions
2. **EBS Volume scanner** - Detect unattached volumes
3. **Elastic IP scanner** - Detect unassociated EIPs
4. **Configuration file** - YAML config for settings instead of CLI args
5. **Whitelisting** - Ignore resources by tag, name pattern, or ID
6. **Dry-run mode** - Simulate what would be detected
7. **JSON export** - For programmatic consumption

## Future Enhancements (Post-MVP)

- Multi-account support (AWS Organizations)
- Web UI dashboard
- Historical tracking (store results in SQLite/DynamoDB)
- Auto-deletion with confirmation
- CloudWatch integration for metrics
- Lambda deployment for scheduled scans
- Terraform/CloudFormation for deployment
- Cost estimation (show potential savings)
- Slack/email notifications
- Additional resource types (Lambda, S3, CloudFront, etc.)

---

## Getting Started (MVP)

### Prerequisites
- Python 3.8+
- AWS account with credentials configured
- IAM permissions for EC2 read access

### Installation
```bash
git clone https://github.com/yourorg/aws-resource-cleaner.git
cd aws-resource-cleaner
pip install -r requirements.txt
```

### Configuration
```bash
# Configure AWS credentials
aws configure

# Or use environment variables
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
export AWS_DEFAULT_REGION=us-east-1
```

### Usage
```bash
# Scan security groups in default region
python -m src.main scan security-groups

# Specify region
python -m src.main scan security-groups --region eu-west-1

# Export to CSV
python -m src.main scan security-groups --output results.csv
```

---

## Development Guidelines

### Code Style
- Follow PEP 8
- Use type hints
- Document all functions with docstrings
- Keep functions small and focused

### Testing
- Write unit tests for all scanner logic
- Mock AWS API calls in tests
- Aim for >80% code coverage

### Error Handling
- Handle AWS API throttling (use exponential backoff)
- Handle credential errors gracefully
- Validate user inputs
- Provide helpful error messages

### Performance
- Use boto3 pagination for large result sets
- Implement caching for repeated API calls
- Consider parallel region scanning (future)

---

## Contributing

(Add contribution guidelines here)

---

## License

MIT License
