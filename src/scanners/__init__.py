"""
Resource Scanners
=================

This module provides scanner implementations for various AWS resource types.

Each scanner identifies unused resources by analyzing resource attachments,
references, and usage patterns across the AWS ecosystem.

Available Scanners
------------------
SecurityGroupScanner
    Scans for unused EC2 security groups.
VPCScanner
    Scans for unused Virtual Private Clouds (VPCs).
SubnetScanner
    Scans for unused subnets.
EIPScanner
    Scans for unused Elastic IP addresses.

Example
-------
>>> from src.scanners import SecurityGroupScanner, VPCScanner, SubnetScanner, EIPScanner
>>> from src.core import AWSClient
>>>
>>> client = AWSClient(region="us-east-1")
>>>
>>> # Scan for unused security groups
>>> sg_scanner = SecurityGroupScanner(client)
>>> sg_result = sg_scanner.scan()
>>> print(f"Found {sg_result.unused_count} unused security groups")
>>>
>>> # Scan for unused VPCs
>>> vpc_scanner = VPCScanner(client, exclude_default=True)
>>> vpc_result = vpc_scanner.scan()
>>> print(f"Found {vpc_result.unused_count} unused VPCs")
>>>
>>> # Scan for unused subnets
>>> subnet_scanner = SubnetScanner(client, exclude_default=True)
>>> subnet_result = subnet_scanner.scan()
>>> print(f"Found {subnet_result.unused_count} unused subnets")
>>>
>>> # Scan for unused Elastic IPs
>>> eip_scanner = EIPScanner(client)
>>> eip_result = eip_scanner.scan()
>>> print(f"Found {eip_result.unused_count} unused Elastic IPs")

Adding New Scanners
-------------------
To add a new scanner:

1. Create a new file in this directory (e.g., `ebs_scanner.py`)
2. Implement a class extending `BaseScanner`
3. Implement the required abstract methods
4. Export the scanner in this `__init__.py`

Example template::

    from src.core.base_scanner import BaseScanner

    class EBSVolumeScanner(BaseScanner):
        def get_resource_type(self) -> str:
            return "ebs_volume"

        def get_all_resources(self):
            # Fetch all EBS volumes
            ...

        def get_resources_in_use(self):
            # Find attached volumes
            ...

See Also
--------
src.core.base_scanner : Base class for all scanners.
"""

from src.scanners.eip_scanner import EIPScanner
from src.scanners.security_group_scanner import SecurityGroupScanner
from src.scanners.subnet_scanner import SubnetScanner
from src.scanners.vpc_scanner import VPCScanner

__all__ = [
    "EIPScanner",
    "SecurityGroupScanner",
    "SubnetScanner",
    "VPCScanner",
]
