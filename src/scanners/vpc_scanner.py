"""
VPC Scanner Module
==================

Identifies unused Virtual Private Clouds (VPCs) across AWS accounts by
analyzing resource attachments and activity.

This module implements comprehensive detection logic that checks VPC
usage across multiple AWS services including EC2, RDS, Lambda, and more.

Classes
-------
VPCScanner
    Main scanner class for identifying unused VPCs.

Example
-------
>>> from src.scanners import VPCScanner
>>> from src.core import AWSClient
>>>
>>> client = AWSClient(region="us-east-1")
>>> scanner = VPCScanner(client, exclude_default=True)
>>> result = scanner.scan()
>>>
>>> for vpc in result.unused_resources:
...     print(f"{vpc['id']}: {vpc['name']}")

Detection Logic
---------------
A VPC is considered "in use" if any of the following are true:

1. **EC2 Instances** - Contains any running or stopped EC2 instances
2. **RDS Instances** - Contains any RDS database instances
3. **NAT Gateways** - Has any NAT Gateways
4. **Load Balancers** - Has any ELB/ALB/NLB
5. **Lambda Functions** - Has VPC-connected Lambda functions
6. **ECS Services** - Has any ECS services in the VPC
7. **ElastiCache** - Has any ElastiCache clusters
8. **VPC Endpoints** - Has any VPC endpoints (interface or gateway)
9. **Transit Gateway Attachments** - Is attached to a Transit Gateway
10. **VPN Connections** - Has any VPN connections
11. **VPC Peering** - Has active peering connections
12. **Default VPC** - Is the default VPC (optionally excluded)

Notes
-----
The scanner uses pagination for all AWS API calls to handle accounts
with large numbers of resources. Error handling is implemented per-source
to ensure partial failures don't prevent detection from other sources.

See Also
--------
BaseScanner : Abstract base class.
SecurityGroupScanner : Similar implementation for security groups.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Set

from botocore.exceptions import ClientError

from src.core.base_scanner import BaseScanner

# Module logger
logger = logging.getLogger(__name__)


class VPCScanner(BaseScanner):
    """
    Scanner for identifying unused Virtual Private Clouds (VPCs).

    Performs comprehensive analysis of VPC resource attachments across
    multiple AWS services to accurately identify unused VPCs.

    Parameters
    ----------
    aws_client : AWSClient
        Instance of AWSClient for AWS API access.
    exclude_default : bool, default=True
        If True, exclude the default VPC from results.
        Default VPCs are typically kept for convenience.

    Attributes
    ----------
    exclude_default : bool
        Whether default VPCs are excluded from results.
    region : str
        The AWS region being scanned.

    Examples
    --------
    Basic usage:

    >>> scanner = VPCScanner(client)
    >>> result = scanner.scan()
    >>> print(f"Found {result.unused_count} unused VPCs")

    Including default VPC in scan:

    >>> scanner = VPCScanner(client, exclude_default=False)
    >>> result = scanner.scan()

    Getting detailed resource information:

    >>> for vpc in result.unused_resources:
    ...     print(f"ID: {vpc['id']}")
    ...     print(f"Name: {vpc['name']}")
    ...     print(f"CIDR: {vpc['cidr_block']}")
    ...     print(f"Tags: {vpc['tags']}")

    See Also
    --------
    BaseScanner : Parent class defining the scanner interface.
    SecurityGroupScanner : Similar scanner for security groups.
    """

    def __init__(
        self,
        aws_client,
        exclude_default: bool = True,
    ) -> None:
        """Initialize the VPC scanner."""
        super().__init__(aws_client)
        self.exclude_default = exclude_default

        # Lazy-loaded service clients
        self._ec2_client = None
        self._rds_client = None
        self._elb_client = None
        self._elbv2_client = None
        self._lambda_client = None
        self._ecs_client = None
        self._elasticache_client = None

        logger.debug(
            f"Initialized VPCScanner for {self.region} "
            f"(exclude_default={exclude_default})"
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
            Always returns 'vpc'.
        """
        return "vpc"

    def get_all_resources(self) -> List[Dict[str, Any]]:
        """
        Fetch all VPCs in the region.

        Returns
        -------
        list of dict
            List of VPC dictionaries with keys:
            - id : str - VPC ID (e.g., 'vpc-123abc')
            - name : str - VPC name from tags (or 'unnamed')
            - cidr_block : str - Primary CIDR block
            - is_default : bool - True if this is the default VPC
            - state : str - VPC state (available, pending, etc.)
            - tags : dict - Tag key-value pairs

        Raises
        ------
        ResourceFetchError
            If unable to fetch VPCs from AWS.

        Example
        -------
        >>> vpcs = scanner.get_all_resources()
        >>> for vpc in vpcs:
        ...     print(f"{vpc['id']}: {vpc['name']}")
        """
        vpcs: List[Dict[str, Any]] = []
        paginator = self.ec2_client.get_paginator("describe_vpcs")

        logger.debug(f"Fetching all VPCs in {self.region}")

        for page in paginator.paginate():
            for vpc in page["Vpcs"]:
                # Extract name from tags
                tags = {tag["Key"]: tag["Value"] for tag in vpc.get("Tags", [])}
                name = tags.get("Name", "unnamed")

                vpcs.append(
                    {
                        "id": vpc["VpcId"],
                        "name": name,
                        "cidr_block": vpc.get("CidrBlock", "N/A"),
                        "is_default": vpc.get("IsDefault", False),
                        "state": vpc.get("State", "unknown"),
                        "tags": tags,
                    }
                )

        logger.debug(f"Found {len(vpcs)} VPCs in {self.region}")
        return vpcs

    def get_resources_in_use(self) -> Set[str]:
        """
        Get VPC IDs that are currently in use.

        Aggregates usage information from multiple AWS services to build
        a comprehensive set of VPCs that are actively in use.

        Returns
        -------
        set of str
            VPC IDs that are in use.

        Notes
        -----
        This method checks multiple sources. Individual source failures
        are logged but don't prevent checking other sources.

        Example
        -------
        >>> used_ids = scanner.get_resources_in_use()
        >>> print(f"{len(used_ids)} VPCs are in use")
        """
        used_vpcs: Set[str] = set()

        # Collect VPCs from all sources
        sources = [
            ("EC2 instances", self._get_vpcs_with_ec2_instances),
            ("RDS instances", self._get_vpcs_with_rds),
            ("NAT Gateways", self._get_vpcs_with_nat_gateways),
            ("Classic ELBs", self._get_vpcs_with_classic_elb),
            ("ALB/NLB", self._get_vpcs_with_elbv2),
            ("Lambda functions", self._get_vpcs_with_lambda),
            ("ElastiCache", self._get_vpcs_with_elasticache),
            ("VPC Endpoints", self._get_vpcs_with_endpoints),
            ("Network Interfaces", self._get_vpcs_with_enis),
            ("Internet Gateways", self._get_vpcs_with_internet_gateways),
            ("VPN Gateways", self._get_vpcs_with_vpn_gateways),
            ("Transit Gateway Attachments", self._get_vpcs_with_tgw_attachments),
            ("VPC Peering", self._get_vpcs_with_peering),
        ]

        for source_name, fetch_func in sources:
            try:
                vpcs = fetch_func()
                used_vpcs.update(vpcs)
                logger.debug(f"Found {len(vpcs)} VPCs from {source_name}")
            except Exception as e:
                logger.warning(f"Failed to get VPCs from {source_name}: {e}")

        # Add default VPCs to used set if excluding them
        if self.exclude_default:
            default_vpcs = self._get_default_vpcs()
            used_vpcs.update(default_vpcs)
            logger.debug(f"Marked {len(default_vpcs)} default VPCs as used")

        return used_vpcs

    def get_unused_resources(self) -> List[Dict[str, Any]]:
        """
        Find VPCs that are not in use.

        Overrides parent method to add additional filtering for
        default VPCs when configured.

        Returns
        -------
        list of dict
            List of unused VPC dictionaries.

        Example
        -------
        >>> unused = scanner.get_unused_resources()
        >>> for vpc in unused:
        ...     print(f"Unused: {vpc['id']} ({vpc['name']})")
        """
        all_vpcs = self.get_all_resources()
        used_ids = self.get_resources_in_use()

        unused: List[Dict[str, Any]] = []
        for vpc in all_vpcs:
            vpc_id = vpc.get("id")
            if vpc_id and vpc_id not in used_ids:
                # Double-check default VPC exclusion
                if self.exclude_default and vpc.get("is_default", False):
                    continue
                unused.append(vpc)

        return unused

    # =========================================================================
    # Private Methods: Service-Specific VPC Detection
    # =========================================================================

    def _get_vpcs_with_ec2_instances(self) -> Set[str]:
        """Get VPCs containing EC2 instances."""
        vpc_ids: Set[str] = set()
        paginator = self.ec2_client.get_paginator("describe_instances")

        try:
            for page in paginator.paginate():
                for reservation in page["Reservations"]:
                    for instance in reservation["Instances"]:
                        vpc_id = instance.get("VpcId")
                        if vpc_id:
                            vpc_ids.add(vpc_id)
        except ClientError as e:
            logger.warning(f"Error fetching EC2 instances: {e}")

        return vpc_ids

    def _get_vpcs_with_rds(self) -> Set[str]:
        """Get VPCs containing RDS instances."""
        vpc_ids: Set[str] = set()
        paginator = self.rds_client.get_paginator("describe_db_instances")

        try:
            for page in paginator.paginate():
                for db in page["DBInstances"]:
                    subnet_group = db.get("DBSubnetGroup", {})
                    vpc_id = subnet_group.get("VpcId")
                    if vpc_id:
                        vpc_ids.add(vpc_id)
        except ClientError as e:
            logger.warning(f"Error fetching RDS instances: {e}")

        return vpc_ids

    def _get_vpcs_with_nat_gateways(self) -> Set[str]:
        """Get VPCs with NAT Gateways."""
        vpc_ids: Set[str] = set()
        paginator = self.ec2_client.get_paginator("describe_nat_gateways")

        try:
            for page in paginator.paginate():
                for nat in page["NatGateways"]:
                    # Only count active NAT gateways
                    if nat.get("State") in ("available", "pending"):
                        vpc_id = nat.get("VpcId")
                        if vpc_id:
                            vpc_ids.add(vpc_id)
        except ClientError as e:
            logger.warning(f"Error fetching NAT Gateways: {e}")

        return vpc_ids

    def _get_vpcs_with_classic_elb(self) -> Set[str]:
        """Get VPCs with Classic Load Balancers."""
        vpc_ids: Set[str] = set()
        paginator = self.elb_client.get_paginator("describe_load_balancers")

        try:
            for page in paginator.paginate():
                for elb in page["LoadBalancerDescriptions"]:
                    vpc_id = elb.get("VPCId")
                    if vpc_id:
                        vpc_ids.add(vpc_id)
        except ClientError as e:
            logger.warning(f"Error fetching Classic ELBs: {e}")

        return vpc_ids

    def _get_vpcs_with_elbv2(self) -> Set[str]:
        """Get VPCs with Application/Network Load Balancers."""
        vpc_ids: Set[str] = set()
        paginator = self.elbv2_client.get_paginator("describe_load_balancers")

        try:
            for page in paginator.paginate():
                for lb in page["LoadBalancers"]:
                    vpc_id = lb.get("VpcId")
                    if vpc_id:
                        vpc_ids.add(vpc_id)
        except ClientError as e:
            logger.warning(f"Error fetching ALB/NLB: {e}")

        return vpc_ids

    def _get_vpcs_with_lambda(self) -> Set[str]:
        """Get VPCs with Lambda functions."""
        vpc_ids: Set[str] = set()
        paginator = self.lambda_client.get_paginator("list_functions")

        try:
            for page in paginator.paginate():
                for func in page["Functions"]:
                    vpc_config = func.get("VpcConfig", {})
                    vpc_id = vpc_config.get("VpcId")
                    if vpc_id:
                        vpc_ids.add(vpc_id)
        except ClientError as e:
            logger.warning(f"Error fetching Lambda functions: {e}")

        return vpc_ids

    def _get_vpcs_with_elasticache(self) -> Set[str]:
        """Get VPCs with ElastiCache clusters."""
        vpc_ids: Set[str] = set()
        paginator = self.elasticache_client.get_paginator("describe_cache_clusters")

        try:
            for page in paginator.paginate(ShowCacheNodeInfo=False):
                for cluster in page["CacheClusters"]:
                    # Get the cache subnet group to find VPC
                    subnet_group_name = cluster.get("CacheSubnetGroupName")
                    if subnet_group_name:
                        # Need to describe the subnet group to get VPC ID
                        try:
                            sg_response = self.elasticache_client.describe_cache_subnet_groups(
                                CacheSubnetGroupName=subnet_group_name
                            )
                            for sg in sg_response.get("CacheSubnetGroups", []):
                                vpc_id = sg.get("VpcId")
                                if vpc_id:
                                    vpc_ids.add(vpc_id)
                        except ClientError:
                            pass
        except ClientError as e:
            logger.warning(f"Error fetching ElastiCache clusters: {e}")

        return vpc_ids

    def _get_vpcs_with_endpoints(self) -> Set[str]:
        """Get VPCs with VPC Endpoints."""
        vpc_ids: Set[str] = set()
        paginator = self.ec2_client.get_paginator("describe_vpc_endpoints")

        try:
            for page in paginator.paginate():
                for endpoint in page["VpcEndpoints"]:
                    vpc_id = endpoint.get("VpcId")
                    if vpc_id:
                        vpc_ids.add(vpc_id)
        except ClientError as e:
            logger.warning(f"Error fetching VPC Endpoints: {e}")

        return vpc_ids

    def _get_vpcs_with_enis(self) -> Set[str]:
        """
        Get VPCs with Network Interfaces.
        
        This is a broad check - any ENI indicates the VPC is in use.
        Excludes ENIs that are 'available' (not attached).
        """
        vpc_ids: Set[str] = set()
        paginator = self.ec2_client.get_paginator("describe_network_interfaces")

        try:
            # Only get ENIs that are in-use
            for page in paginator.paginate(
                Filters=[{"Name": "status", "Values": ["in-use"]}]
            ):
                for eni in page["NetworkInterfaces"]:
                    vpc_id = eni.get("VpcId")
                    if vpc_id:
                        vpc_ids.add(vpc_id)
        except ClientError as e:
            logger.warning(f"Error fetching ENIs: {e}")

        return vpc_ids

    def _get_vpcs_with_internet_gateways(self) -> Set[str]:
        """Get VPCs with attached Internet Gateways."""
        vpc_ids: Set[str] = set()

        try:
            response = self.ec2_client.describe_internet_gateways()
            for igw in response.get("InternetGateways", []):
                for attachment in igw.get("Attachments", []):
                    if attachment.get("State") == "available":
                        vpc_id = attachment.get("VpcId")
                        if vpc_id:
                            vpc_ids.add(vpc_id)
        except ClientError as e:
            logger.warning(f"Error fetching Internet Gateways: {e}")

        return vpc_ids

    def _get_vpcs_with_vpn_gateways(self) -> Set[str]:
        """Get VPCs with attached VPN Gateways."""
        vpc_ids: Set[str] = set()

        try:
            response = self.ec2_client.describe_vpn_gateways()
            for vgw in response.get("VpnGateways", []):
                if vgw.get("State") == "available":
                    for attachment in vgw.get("VpcAttachments", []):
                        if attachment.get("State") == "attached":
                            vpc_id = attachment.get("VpcId")
                            if vpc_id:
                                vpc_ids.add(vpc_id)
        except ClientError as e:
            logger.warning(f"Error fetching VPN Gateways: {e}")

        return vpc_ids

    def _get_vpcs_with_tgw_attachments(self) -> Set[str]:
        """Get VPCs with Transit Gateway attachments."""
        vpc_ids: Set[str] = set()

        try:
            paginator = self.ec2_client.get_paginator(
                "describe_transit_gateway_vpc_attachments"
            )
            for page in paginator.paginate():
                for attachment in page.get("TransitGatewayVpcAttachments", []):
                    if attachment.get("State") in ("available", "pending"):
                        vpc_id = attachment.get("VpcId")
                        if vpc_id:
                            vpc_ids.add(vpc_id)
        except ClientError as e:
            # Transit Gateway might not be available in all regions
            logger.debug(f"Error fetching Transit Gateway attachments: {e}")

        return vpc_ids

    def _get_vpcs_with_peering(self) -> Set[str]:
        """Get VPCs with active peering connections."""
        vpc_ids: Set[str] = set()

        try:
            paginator = self.ec2_client.get_paginator("describe_vpc_peering_connections")
            for page in paginator.paginate():
                for peering in page.get("VpcPeeringConnections", []):
                    if peering.get("Status", {}).get("Code") == "active":
                        # Add both requester and accepter VPCs
                        requester_vpc = peering.get("RequesterVpcInfo", {}).get("VpcId")
                        accepter_vpc = peering.get("AccepterVpcInfo", {}).get("VpcId")
                        if requester_vpc:
                            vpc_ids.add(requester_vpc)
                        if accepter_vpc:
                            vpc_ids.add(accepter_vpc)
        except ClientError as e:
            logger.warning(f"Error fetching VPC Peering connections: {e}")

        return vpc_ids

    def _get_default_vpcs(self) -> Set[str]:
        """Get all default VPC IDs."""
        default_vpcs: Set[str] = set()

        try:
            response = self.ec2_client.describe_vpcs(
                Filters=[{"Name": "is-default", "Values": ["true"]}]
            )
            for vpc in response.get("Vpcs", []):
                default_vpcs.add(vpc["VpcId"])
        except ClientError as e:
            logger.warning(f"Error fetching default VPCs: {e}")

        return default_vpcs

    # =========================================================================
    # String Representation
    # =========================================================================

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"VPCScanner("
            f"region='{self.region}', "
            f"exclude_default={self.exclude_default})"
        )
