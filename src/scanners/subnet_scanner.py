"""
Subnet Scanner Module
=====================

Identifies unused subnets across AWS accounts by analyzing resource
deployments and network interface attachments.

This module implements comprehensive detection logic that checks subnet
usage across multiple AWS services including EC2, RDS, Lambda, and more.

Classes
-------
SubnetScanner
    Main scanner class for identifying unused subnets.

Example
-------
>>> from src.scanners import SubnetScanner
>>> from src.core import AWSClient
>>>
>>> client = AWSClient(region="us-east-1")
>>> scanner = SubnetScanner(client, exclude_default=True)
>>> result = scanner.scan()
>>>
>>> for subnet in result.unused_resources:
...     print(f"{subnet['id']}: {subnet['name']} ({subnet['cidr_block']})")

Detection Logic
---------------
A subnet is considered "in use" if any of the following are true:

1. **EC2 Instances** - Contains any running or stopped EC2 instances
2. **Network Interfaces** - Has any ENIs in use (covers most services)
3. **RDS Instances** - Part of an RDS DB subnet group
4. **NAT Gateways** - Has a NAT Gateway deployed
5. **Load Balancers** - Used by any ELB/ALB/NLB
6. **Lambda Functions** - Has VPC-connected Lambda functions
7. **ElastiCache** - Part of an ElastiCache subnet group
8. **ECS Tasks** - Has running ECS tasks
9. **VPC Endpoints** - Has VPC endpoint interfaces
10. **Default Subnet** - Is a default subnet (optionally excluded)

Notes
-----
The scanner uses pagination for all AWS API calls to handle accounts
with large numbers of resources. Error handling is implemented per-source
to ensure partial failures don't prevent detection from other sources.

See Also
--------
BaseScanner : Abstract base class.
VPCScanner : Similar implementation for VPCs.
SecurityGroupScanner : Similar implementation for security groups.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Set

from botocore.exceptions import ClientError

from src.core.base_scanner import BaseScanner

# Module logger
logger = logging.getLogger(__name__)


class SubnetScanner(BaseScanner):
    """
    Scanner for identifying unused subnets.

    Performs comprehensive analysis of subnet resource deployments across
    multiple AWS services to accurately identify unused subnets.

    Parameters
    ----------
    aws_client : AWSClient
        Instance of AWSClient for AWS API access.
    exclude_default : bool, default=True
        If True, exclude default subnets from results.
        Default subnets are created automatically with default VPCs.
    vpc_id : str, optional
        If provided, only scan subnets in this specific VPC.

    Attributes
    ----------
    exclude_default : bool
        Whether default subnets are excluded from results.
    vpc_id : str or None
        VPC filter if specified.
    region : str
        The AWS region being scanned.

    Examples
    --------
    Basic usage:

    >>> scanner = SubnetScanner(client)
    >>> result = scanner.scan()
    >>> print(f"Found {result.unused_count} unused subnets")

    Scanning a specific VPC:

    >>> scanner = SubnetScanner(client, vpc_id="vpc-12345678")
    >>> result = scanner.scan()

    Including default subnets:

    >>> scanner = SubnetScanner(client, exclude_default=False)
    >>> result = scanner.scan()

    Getting detailed resource information:

    >>> for subnet in result.unused_resources:
    ...     print(f"ID: {subnet['id']}")
    ...     print(f"Name: {subnet['name']}")
    ...     print(f"CIDR: {subnet['cidr_block']}")
    ...     print(f"AZ: {subnet['availability_zone']}")
    ...     print(f"VPC: {subnet['vpc_id']}")

    See Also
    --------
    BaseScanner : Parent class defining the scanner interface.
    VPCScanner : Scanner for unused VPCs.
    """

    def __init__(
        self,
        aws_client,
        exclude_default: bool = True,
        vpc_id: str = None,
    ) -> None:
        """Initialize the subnet scanner."""
        super().__init__(aws_client)
        self.exclude_default = exclude_default
        self.vpc_id = vpc_id

        # Lazy-loaded service clients
        self._ec2_client = None
        self._rds_client = None
        self._elb_client = None
        self._elbv2_client = None
        self._lambda_client = None
        self._elasticache_client = None

        logger.debug(
            f"Initialized SubnetScanner for {self.region} "
            f"(exclude_default={exclude_default}, vpc_id={vpc_id})"
        )

    # =========================================================================
    # Service Client Properties (Lazy Loading)
    # =========================================================================

    @property
    def ec2_client(self):
        """Get EC2 client (lazy loaded)."""
        if self._ec2_client is None:
            self._ec2_client = self.aws_client.get_ec2_client()
        return self._ec2_client

    @property
    def rds_client(self):
        """Get RDS client (lazy loaded)."""
        if self._rds_client is None:
            self._rds_client = self.aws_client.get_rds_client()
        return self._rds_client

    @property
    def elb_client(self):
        """Get Classic ELB client (lazy loaded)."""
        if self._elb_client is None:
            self._elb_client = self.aws_client.get_elb_client()
        return self._elb_client

    @property
    def elbv2_client(self):
        """Get ALB/NLB client (lazy loaded)."""
        if self._elbv2_client is None:
            self._elbv2_client = self.aws_client.get_elbv2_client()
        return self._elbv2_client

    @property
    def lambda_client(self):
        """Get Lambda client (lazy loaded)."""
        if self._lambda_client is None:
            self._lambda_client = self.aws_client.get_lambda_client()
        return self._lambda_client

    @property
    def elasticache_client(self):
        """Get ElastiCache client (lazy loaded)."""
        if self._elasticache_client is None:
            self._elasticache_client = self.aws_client.get_elasticache_client()
        return self._elasticache_client

    # =========================================================================
    # BaseScanner Abstract Method Implementations
    # =========================================================================

    def get_resource_type(self) -> str:
        """
        Get the resource type identifier.

        Returns
        -------
        str
            Always returns 'subnet'.
        """
        return "subnet"

    def get_all_resources(self) -> List[Dict[str, Any]]:
        """
        Fetch all subnets in the region.

        Returns
        -------
        list of dict
            List of subnet dictionaries with keys:
            - id : str - Subnet ID (e.g., 'subnet-123abc')
            - name : str - Subnet name from tags (or 'unnamed')
            - cidr_block : str - CIDR block
            - vpc_id : str - Parent VPC ID
            - availability_zone : str - AZ name
            - availability_zone_id : str - AZ ID
            - is_default : bool - True if this is a default subnet
            - state : str - Subnet state
            - available_ips : int - Available IP addresses
            - tags : dict - Tag key-value pairs

        Raises
        ------
        ResourceFetchError
            If unable to fetch subnets from AWS.

        Example
        -------
        >>> subnets = scanner.get_all_resources()
        >>> for subnet in subnets:
        ...     print(f"{subnet['id']}: {subnet['cidr_block']} in {subnet['availability_zone']}")
        """
        subnets: List[Dict[str, Any]] = []
        paginator = self.ec2_client.get_paginator("describe_subnets")

        # Build filters
        filters = []
        if self.vpc_id:
            filters.append({"Name": "vpc-id", "Values": [self.vpc_id]})

        logger.debug(f"Fetching all subnets in {self.region}")

        paginate_kwargs = {}
        if filters:
            paginate_kwargs["Filters"] = filters

        for page in paginator.paginate(**paginate_kwargs):
            for subnet in page["Subnets"]:
                # Extract name from tags
                tags = {tag["Key"]: tag["Value"] for tag in subnet.get("Tags", [])}
                name = tags.get("Name", "unnamed")

                subnets.append(
                    {
                        "id": subnet["SubnetId"],
                        "name": name,
                        "cidr_block": subnet.get("CidrBlock", "N/A"),
                        "vpc_id": subnet.get("VpcId", "N/A"),
                        "availability_zone": subnet.get("AvailabilityZone", "N/A"),
                        "availability_zone_id": subnet.get("AvailabilityZoneId", "N/A"),
                        "is_default": subnet.get("DefaultForAz", False),
                        "state": subnet.get("State", "unknown"),
                        "available_ips": subnet.get("AvailableIpAddressCount", 0),
                        "tags": tags,
                    }
                )

        logger.debug(f"Found {len(subnets)} subnets in {self.region}")
        return subnets

    def get_resources_in_use(self) -> Set[str]:
        """
        Get subnet IDs that are currently in use.

        Aggregates usage information from multiple AWS services to build
        a comprehensive set of subnets that are actively in use.

        Returns
        -------
        set of str
            Subnet IDs that are in use.

        Notes
        -----
        This method checks multiple sources. Individual source failures
        are logged but don't prevent checking other sources.

        Example
        -------
        >>> used_ids = scanner.get_resources_in_use()
        >>> print(f"{len(used_ids)} subnets are in use")
        """
        used_subnets: Set[str] = set()

        # Collect subnets from all sources
        sources = [
            ("EC2 instances", self._get_subnets_with_ec2_instances),
            ("Network Interfaces", self._get_subnets_with_enis),
            ("NAT Gateways", self._get_subnets_with_nat_gateways),
            ("RDS subnet groups", self._get_subnets_in_rds_groups),
            ("Classic ELBs", self._get_subnets_with_classic_elb),
            ("ALB/NLB", self._get_subnets_with_elbv2),
            ("Lambda functions", self._get_subnets_with_lambda),
            ("ElastiCache subnet groups", self._get_subnets_in_elasticache_groups),
            ("VPC Endpoints", self._get_subnets_with_endpoints),
        ]

        for source_name, fetch_func in sources:
            try:
                subnets = fetch_func()
                used_subnets.update(subnets)
                logger.debug(f"Found {len(subnets)} subnets from {source_name}")
            except Exception as e:
                logger.warning(f"Failed to get subnets from {source_name}: {e}")

        # Add default subnets to used set if excluding them
        if self.exclude_default:
            default_subnets = self._get_default_subnets()
            used_subnets.update(default_subnets)
            logger.debug(f"Marked {len(default_subnets)} default subnets as used")

        return used_subnets

    def get_unused_resources(self) -> List[Dict[str, Any]]:
        """
        Find subnets that are not in use.

        Overrides parent method to add additional filtering for
        default subnets when configured.

        Returns
        -------
        list of dict
            List of unused subnet dictionaries.

        Example
        -------
        >>> unused = scanner.get_unused_resources()
        >>> for subnet in unused:
        ...     print(f"Unused: {subnet['id']} ({subnet['cidr_block']})")
        """
        all_subnets = self.get_all_resources()
        used_ids = self.get_resources_in_use()

        unused: List[Dict[str, Any]] = []
        for subnet in all_subnets:
            subnet_id = subnet.get("id")
            if subnet_id and subnet_id not in used_ids:
                # Double-check default subnet exclusion
                if self.exclude_default and subnet.get("is_default", False):
                    continue
                unused.append(subnet)

        return unused

    # =========================================================================
    # Private Methods: Service-Specific Subnet Detection
    # =========================================================================

    def _get_subnets_with_ec2_instances(self) -> Set[str]:
        """Get subnets containing EC2 instances."""
        subnet_ids: Set[str] = set()
        paginator = self.ec2_client.get_paginator("describe_instances")

        try:
            filters = []
            if self.vpc_id:
                filters.append({"Name": "vpc-id", "Values": [self.vpc_id]})

            paginate_kwargs = {}
            if filters:
                paginate_kwargs["Filters"] = filters

            for page in paginator.paginate(**paginate_kwargs):
                for reservation in page["Reservations"]:
                    for instance in reservation["Instances"]:
                        subnet_id = instance.get("SubnetId")
                        if subnet_id:
                            subnet_ids.add(subnet_id)
        except ClientError as e:
            logger.warning(f"Error fetching EC2 instances: {e}")

        return subnet_ids

    def _get_subnets_with_enis(self) -> Set[str]:
        """
        Get subnets with Network Interfaces in use.

        This is a comprehensive check as most AWS services create ENIs.
        """
        subnet_ids: Set[str] = set()
        paginator = self.ec2_client.get_paginator("describe_network_interfaces")

        try:
            # Only get ENIs that are in-use
            filters = [{"Name": "status", "Values": ["in-use"]}]
            if self.vpc_id:
                filters.append({"Name": "vpc-id", "Values": [self.vpc_id]})

            for page in paginator.paginate(Filters=filters):
                for eni in page["NetworkInterfaces"]:
                    subnet_id = eni.get("SubnetId")
                    if subnet_id:
                        subnet_ids.add(subnet_id)
        except ClientError as e:
            logger.warning(f"Error fetching ENIs: {e}")

        return subnet_ids

    def _get_subnets_with_nat_gateways(self) -> Set[str]:
        """Get subnets with NAT Gateways."""
        subnet_ids: Set[str] = set()
        paginator = self.ec2_client.get_paginator("describe_nat_gateways")

        try:
            filters = [{"Name": "state", "Values": ["available", "pending"]}]
            if self.vpc_id:
                filters.append({"Name": "vpc-id", "Values": [self.vpc_id]})

            for page in paginator.paginate(Filters=filters):
                for nat in page["NatGateways"]:
                    subnet_id = nat.get("SubnetId")
                    if subnet_id:
                        subnet_ids.add(subnet_id)
        except ClientError as e:
            logger.warning(f"Error fetching NAT Gateways: {e}")

        return subnet_ids

    def _get_subnets_in_rds_groups(self) -> Set[str]:
        """Get subnets that are part of RDS DB subnet groups."""
        subnet_ids: Set[str] = set()
        paginator = self.rds_client.get_paginator("describe_db_subnet_groups")

        try:
            for page in paginator.paginate():
                for group in page["DBSubnetGroups"]:
                    # Filter by VPC if specified
                    if self.vpc_id and group.get("VpcId") != self.vpc_id:
                        continue

                    for subnet in group.get("Subnets", []):
                        subnet_id = subnet.get("SubnetIdentifier")
                        if subnet_id:
                            subnet_ids.add(subnet_id)
        except ClientError as e:
            logger.warning(f"Error fetching RDS subnet groups: {e}")

        return subnet_ids

    def _get_subnets_with_classic_elb(self) -> Set[str]:
        """Get subnets with Classic Load Balancers."""
        subnet_ids: Set[str] = set()
        paginator = self.elb_client.get_paginator("describe_load_balancers")

        try:
            for page in paginator.paginate():
                for elb in page["LoadBalancerDescriptions"]:
                    # Filter by VPC if specified
                    if self.vpc_id and elb.get("VPCId") != self.vpc_id:
                        continue

                    for subnet_id in elb.get("Subnets", []):
                        subnet_ids.add(subnet_id)
        except ClientError as e:
            logger.warning(f"Error fetching Classic ELBs: {e}")

        return subnet_ids

    def _get_subnets_with_elbv2(self) -> Set[str]:
        """Get subnets with Application/Network Load Balancers."""
        subnet_ids: Set[str] = set()
        paginator = self.elbv2_client.get_paginator("describe_load_balancers")

        try:
            for page in paginator.paginate():
                for lb in page["LoadBalancers"]:
                    # Filter by VPC if specified
                    if self.vpc_id and lb.get("VpcId") != self.vpc_id:
                        continue

                    for az in lb.get("AvailabilityZones", []):
                        subnet_id = az.get("SubnetId")
                        if subnet_id:
                            subnet_ids.add(subnet_id)
        except ClientError as e:
            logger.warning(f"Error fetching ALB/NLB: {e}")

        return subnet_ids

    def _get_subnets_with_lambda(self) -> Set[str]:
        """Get subnets with Lambda functions."""
        subnet_ids: Set[str] = set()
        paginator = self.lambda_client.get_paginator("list_functions")

        try:
            for page in paginator.paginate():
                for func in page["Functions"]:
                    vpc_config = func.get("VpcConfig", {})

                    # Filter by VPC if specified
                    if self.vpc_id and vpc_config.get("VpcId") != self.vpc_id:
                        continue

                    for subnet_id in vpc_config.get("SubnetIds", []):
                        subnet_ids.add(subnet_id)
        except ClientError as e:
            logger.warning(f"Error fetching Lambda functions: {e}")

        return subnet_ids

    def _get_subnets_in_elasticache_groups(self) -> Set[str]:
        """Get subnets that are part of ElastiCache subnet groups."""
        subnet_ids: Set[str] = set()
        paginator = self.elasticache_client.get_paginator("describe_cache_subnet_groups")

        try:
            for page in paginator.paginate():
                for group in page["CacheSubnetGroups"]:
                    # Filter by VPC if specified
                    if self.vpc_id and group.get("VpcId") != self.vpc_id:
                        continue

                    for subnet in group.get("Subnets", []):
                        subnet_id = subnet.get("SubnetIdentifier")
                        if subnet_id:
                            subnet_ids.add(subnet_id)
        except ClientError as e:
            logger.warning(f"Error fetching ElastiCache subnet groups: {e}")

        return subnet_ids

    def _get_subnets_with_endpoints(self) -> Set[str]:
        """Get subnets with VPC Endpoints (interface type)."""
        subnet_ids: Set[str] = set()
        paginator = self.ec2_client.get_paginator("describe_vpc_endpoints")

        try:
            filters = []
            if self.vpc_id:
                filters.append({"Name": "vpc-id", "Values": [self.vpc_id]})

            paginate_kwargs = {}
            if filters:
                paginate_kwargs["Filters"] = filters

            for page in paginator.paginate(**paginate_kwargs):
                for endpoint in page["VpcEndpoints"]:
                    # Only interface endpoints have subnets
                    for subnet_id in endpoint.get("SubnetIds", []):
                        subnet_ids.add(subnet_id)
        except ClientError as e:
            logger.warning(f"Error fetching VPC Endpoints: {e}")

        return subnet_ids

    def _get_default_subnets(self) -> Set[str]:
        """Get all default subnet IDs."""
        default_subnets: Set[str] = set()

        try:
            filters = [{"Name": "default-for-az", "Values": ["true"]}]
            if self.vpc_id:
                filters.append({"Name": "vpc-id", "Values": [self.vpc_id]})

            response = self.ec2_client.describe_subnets(Filters=filters)
            for subnet in response.get("Subnets", []):
                default_subnets.add(subnet["SubnetId"])
        except ClientError as e:
            logger.warning(f"Error fetching default subnets: {e}")

        return default_subnets

    # =========================================================================
    # String Representation
    # =========================================================================

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"SubnetScanner("
            f"region='{self.region}', "
            f"exclude_default={self.exclude_default}, "
            f"vpc_id={self.vpc_id!r})"
        )
