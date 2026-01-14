# MVP Implementation Guide - Start Here

## The Absolute Smallest Feature (Your First PR)

### Feature: List All Security Groups in a Region

**Goal**: Before we can detect unused security groups, we need to be able to list them all.

**Time Estimate**: 2-3 hours

**Deliverable**: A Python script that connects to AWS and prints all security groups in a region.

---

## Step-by-Step Implementation

### Step 1: Project Setup (30 minutes)

```bash
# Create project directory
mkdir aws-resource-cleaner
cd aws-resource-cleaner

# Create Python virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Create project structure
mkdir -p src/scanners src/reporters tests
touch src/__init__.py
touch src/scanners/__init__.py
touch src/reporters/__init__.py
touch requirements.txt
touch .gitignore
touch README.md
```

**requirements.txt:**
```
boto3==1.34.34
```

**.gitignore:**
```
venv/
__pycache__/
*.pyc
.env
*.csv
*.json
.DS_Store
```

Install dependencies:
```bash
pip install -r requirements.txt
```

---

### Step 2: Create AWS Client Wrapper (30 minutes)

**File**: `src/aws_client.py`

```python
"""
AWS Client wrapper for managing boto3 connections
"""
import boto3
from botocore.exceptions import ClientError, NoCredentialsError


class AWSClient:
    """Wrapper around boto3 to manage AWS connections"""
    
    def __init__(self, region='us-east-1', profile=None):
        """
        Initialize AWS client
        
        Args:
            region (str): AWS region to connect to
            profile (str): AWS profile name from ~/.aws/credentials
        """
        self.region = region
        self.profile = profile
        self.session = self._create_session()
        
    def _create_session(self):
        """Create boto3 session with optional profile"""
        try:
            if self.profile:
                return boto3.Session(
                    profile_name=self.profile,
                    region_name=self.region
                )
            else:
                return boto3.Session(region_name=self.region)
        except Exception as e:
            raise Exception(f"Failed to create AWS session: {str(e)}")
    
    def get_ec2_client(self):
        """Get EC2 client"""
        try:
            return self.session.client('ec2')
        except NoCredentialsError:
            raise Exception(
                "AWS credentials not found. "
                "Please configure AWS credentials using 'aws configure' "
                "or set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables."
            )
        except Exception as e:
            raise Exception(f"Failed to create EC2 client: {str(e)}")
```

---

### Step 3: Create Security Group Scanner - Basic Version (1 hour)

**File**: `src/scanners/security_group_scanner.py`

```python
"""
Scanner for AWS Security Groups
"""
from typing import List, Dict


class SecurityGroupScanner:
    """Scanner to find unused security groups"""
    
    def __init__(self, aws_client):
        """
        Initialize scanner
        
        Args:
            aws_client: Instance of AWSClient
        """
        self.aws_client = aws_client
        self.ec2_client = aws_client.get_ec2_client()
        
    def get_all_security_groups(self) -> List[Dict]:
        """
        Fetch all security groups in the region
        
        Returns:
            List of security group dictionaries with relevant fields
        """
        try:
            response = self.ec2_client.describe_security_groups()
            security_groups = []
            
            for sg in response['SecurityGroups']:
                security_groups.append({
                    'id': sg['GroupId'],
                    'name': sg['GroupName'],
                    'description': sg['Description'],
                    'vpc_id': sg.get('VpcId', 'N/A'),
                })
            
            return security_groups
            
        except Exception as e:
            raise Exception(f"Failed to fetch security groups: {str(e)}")
```

---

### Step 4: Create Simple CLI Reporter (30 minutes)

**File**: `src/reporters/cli_reporter.py`

```python
"""
CLI reporter for displaying results in terminal
"""
from typing import List, Dict


class CLIReporter:
    """Reporter to display results in CLI"""
    
    def report_security_groups(self, security_groups: List[Dict]):
        """
        Print security groups in a formatted table
        
        Args:
            security_groups: List of security group dictionaries
        """
        if not security_groups:
            print("No security groups found.")
            return
        
        print(f"\n Found {len(security_groups)} security groups:\n")
        
        # Print header
        print(f"{'ID':<25} {'Name':<30} {'VPC ID':<25} {'Description':<50}")
        print("-" * 130)
        
        # Print each security group
        for sg in security_groups:
            sg_id = sg['id'][:24]
            sg_name = sg['name'][:29]
            vpc_id = sg['vpc_id'][:24]
            description = sg['description'][:49]
            
            print(f"{sg_id:<25} {sg_name:<30} {vpc_id:<25} {description:<50}")
        
        print()
```

---

### Step 5: Create Main Entry Point (30 minutes)

**File**: `src/main.py`

```python
"""
Main entry point for AWS Resource Cleaner
"""
import argparse
import sys
from aws_client import AWSClient
from scanners.security_group_scanner import SecurityGroupScanner
from reporters.cli_reporter import CLIReporter


def main():
    """Main function"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description='AWS Resource Cleaner - Find unused AWS resources'
    )
    parser.add_argument(
        '--region',
        default='us-east-1',
        help='AWS region to scan (default: us-east-1)'
    )
    parser.add_argument(
        '--profile',
        default=None,
        help='AWS profile name from ~/.aws/credentials'
    )
    
    args = parser.parse_args()
    
    try:
        # Initialize AWS client
        print(f"Connecting to AWS region: {args.region}...")
        aws_client = AWSClient(region=args.region, profile=args.profile)
        
        # Initialize scanner
        print("Scanning security groups...")
        scanner = SecurityGroupScanner(aws_client)
        
        # Get all security groups
        security_groups = scanner.get_all_security_groups()
        
        # Report results
        reporter = CLIReporter()
        reporter.report_security_groups(security_groups)
        
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
```

---

### Step 6: Test It! (15 minutes)

```bash
# Make sure you're in the project directory with venv activated
cd aws-resource-cleaner
source venv/bin/activate

# Run the script
python -m src.main

# Or with specific region
python -m src.main --region us-west-2

# Or with AWS profile
python -m src.main --profile my-aws-profile
```

**Expected Output:**
```
Connecting to AWS region: us-east-1...
Scanning security groups...

 Found 45 security groups:

ID                        Name                           VPC ID                    Description
----------------------------------------------------------------------------------------------------------------------------------
sg-0123456789abcdef       default                        vpc-abc123                default VPC security group
sg-9876543210fedcba       web-server-sg                  vpc-xyz789                Web server security group
sg-1111222233334444       database-sg                    vpc-xyz789                Database security group
...
```

---

## Validation Checklist

Before moving to the next feature, make sure:

- [ ] Script runs without errors
- [ ] You can see all security groups in your AWS account
- [ ] Output is readable and formatted
- [ ] Error messages are helpful if credentials are missing
- [ ] Works with different regions (test with --region flag)
- [ ] Code is clean and follows Python conventions

---

## Next Steps (After This Works)

Once you have this basic feature working, the next smallest increment is:

**Feature 2: Identify Which Security Groups Are Unused**

Add a new method to `SecurityGroupScanner`:

```python
def get_unused_security_groups(self) -> List[Dict]:
    """
    Find security groups that are not attached to any resource
    
    Returns:
        List of unused security group dictionaries
    """
    # 1. Get all security groups
    all_sgs = self.get_all_security_groups()
    all_sg_ids = {sg['id'] for sg in all_sgs}
    
    # 2. Get security groups in use by EC2 instances
    used_sg_ids = set()
    
    # Check EC2 instances
    instances = self.ec2_client.describe_instances()
    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            for sg in instance['SecurityGroups']:
                used_sg_ids.add(sg['GroupId'])
    
    # Check Network Interfaces
    enis = self.ec2_client.describe_network_interfaces()
    for eni in enis['NetworkInterfaces']:
        for sg in eni['Groups']:
            used_sg_ids.add(sg['GroupId'])
    
    # 3. Find unused (all - used)
    unused_sg_ids = all_sg_ids - used_sg_ids
    
    # 4. Filter to get full details of unused SGs
    unused_sgs = [sg for sg in all_sgs if sg['id'] in unused_sg_ids]
    
    return unused_sgs
```

Then update `main.py` to call this method instead.

---

## Tips for Development

1. **Test with a small AWS account first** - Don't test on production!
2. **Use print statements liberally** - Add debug prints to understand flow
3. **Handle errors gracefully** - AWS APIs can fail, add try-catch blocks
4. **Start simple** - Don't over-engineer, add features incrementally
5. **Commit often** - Commit after each working feature
6. **Read boto3 docs** - https://boto3.amazonaws.com/v1/documentation/api/latest/index.html

---

## Common Issues & Solutions

**Issue**: `NoCredentialsError`
**Solution**: Run `aws configure` or set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY

**Issue**: `ClientError: An error occurred (UnauthorizedOperation)`
**Solution**: Your IAM user/role needs `ec2:DescribeSecurityGroups` permission

**Issue**: Script is slow
**Solution**: Normal for large accounts. We'll add pagination and caching later.

**Issue**: Not seeing all security groups
**Solution**: Make sure you're scanning the right region with `--region` flag

---

## Success Criteria

You've successfully completed the first feature when:

✅ You can run the script and see a list of all security groups
✅ The output is readable and properly formatted  
✅ Error handling works (try with wrong credentials, wrong region)
✅ Code is committed to git with a good commit message

**Estimated total time: 2-3 hours**

Once this works, you have a solid foundation to build the rest of the MVP!