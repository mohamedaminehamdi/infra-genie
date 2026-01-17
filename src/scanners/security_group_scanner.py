"""
Security Group Scanner Module
=============================

Identifies unused EC2 Security Groups across AWS accounts by analyzing
resource attachments and cross-references.

This module implements comprehensive detection logic that checks security
group usage across multiple AWS services including EC2, RDS, ELB, Lambda,
ECS, and more.

Classes
-------
SecurityGroupScanner
    Main scanner class for identifying unused security groups.

Example
-------
>>> from src.scanners import SecurityGroupScanner
>>> from src.core import AWSClient
>>>
>>> client = AWSClient(region="us-east-1")
>>> scanner = SecurityGroupScanner(client, exclude_default=True)
>>> result = scanner.scan()
>>>
>>> for sg in result.unused_resources:
...     print(f"{sg['id']}: {sg['name']}")

Detection Logic
---------------
A security group is considered "in use" if any of the following are true:

1. **EC2 Instances** - Attached to any running or stopped EC2 instance
2. **Network Interfaces (ENIs)** - Attached to any ENI, which covers:
   - Lambda functions in VPC
   - ECS tasks
   - ElastiCache clusters
   - Elasticsearch domains
   - VPC endpoints
   - NAT Gateways
   - Transit Gateway attachments
3. **RDS Instances** - Associated with any RDS database instance
4. **Classic Load Balancers** - Attached to any Classic ELB
5. **Application/Network Load Balancers** - Attached to any ALB or NLB
6. **Security Group References** - Referenced in another SG's inbound/outbound rules
7. **Default VPC SG** - Is the default security group for a VPC (optionally excluded)

Notes
-----
The scanner uses pagination for all AWS API calls to handle accounts
with large numbers of resources. Error handling is implemented per-source
to ensure partial failures don't prevent detection from other sources.

See Also
--------
BaseScanner : Abstract base class.
RegionManager : For multi-region scanning.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Set

from botocore.exceptions import ClientError

from src.core.base_scanner import BaseScanner

# Module logger
logger = logging.getLogger(__name__)


class SecurityGroupScanner(BaseScanner):
    """
    Scanner for identifying unused EC2 Security Groups.

    Performs comprehensive analysis of security group attachments across
    multiple AWS services to accurately identify unused resources.

    Parameters
    ----------
    aws_client : AWSClient
        Instance of AWSClient for AWS API access.
    exclude_default : bool, default=True
        If True, exclude default VPC security groups from results.
        Default SGs cannot be deleted and are typically not useful to report.

    Attributes
    ----------
    exclude_default : bool
        Whether default SGs are excluded from results.
    region : str
        The AWS region being scanned.

    Examples
    --------
    Basic usage:

    >>> scanner = SecurityGroupScanner(client)
    >>> result = scanner.scan()
    >>> print(f"Found {result.unused_count} unused security groups")

    Including default security groups in scan:

    >>> scanner = SecurityGroupScanner(client, exclude_default=False)
    >>> result = scanner.scan()

    Getting detailed resource information:

    >>> for sg in result.unused_resources:
    ...     print(f"ID: {sg['id']}")
    ...     print(f"Name: {sg['name']}")
    ...     print(f"VPC: {sg['vpc_id']}")
    ...     print(f"Tags: {sg['tags']}")

    See Also
    --------
    BaseScanner : Parent class defining the scanner interface.
    SecurityGroupCleaner : For deleting unused security groups.
    """

    def __init__(
        self,
        aws_client,
        exclude_default: bool = True,
    ) -> None:
        """Initialize the security group scanner."""
        super().__init__(aws_client)
        self.exclude_default = exclude_default

        # Lazy-loaded service clients
        self._ec2_client = None
        self._rds_client = None
        self._elb_client = None
        self._elbv2_client = None

        logger.debug(
            f"Initialized SecurityGroupScanner for {self.region} "
            f"(exclude_default={exclude_default})"
        )

    # =========================================================================
    # Service Client Properties (Lazy Loading)
    # =========================================================================

    @property
    def ec2_client(self):
        """
        Get EC2 client (lazy loaded).

        Returns
        -------
        EC2.Client
            Boto3 EC2 client.
        """
        if self._ec2_client is None:
            self._ec2_client = self.aws_client.get_ec2_client()
        return self._ec2_client

    @property
    def rds_client(self):
        """
        Get RDS client (lazy loaded).

        Returns
        -------
        RDS.Client
            Boto3 RDS client.
        """
        if self._rds_client is None:
            self._rds_client = self.aws_client.get_rds_client()
        return self._rds_client

    @property
    def elb_client(self):
        """
        Get Classic ELB client (lazy loaded).

        Returns
        -------
        ELB.Client
            Boto3 ELB client.
        """
        if self._elb_client is None:
            self._elb_client = self.aws_client.get_elb_client()
        return self._elb_client

    @property
    def elbv2_client(self):
        """
        Get ALB/NLB client (lazy loaded).

        Returns
        -------
        ELBv2.Client
            Boto3 ELBv2 client.
        """
        if self._elbv2_client is None:
            self._elbv2_client = self.aws_client.get_elbv2_client()
        return self._elbv2_client

    # =========================================================================
    # BaseScanner Abstract Method Implementations
    # =========================================================================

    def get_resource_type(self) -> str:
        """
        Get the resource type identifier.

        Returns
        -------
        str
            Always returns 'security_group'.
        """
        return "security_group"

    def get_all_resources(self) -> List[Dict[str, Any]]:
        """
        Fetch all security groups in the region.

        Returns
        -------
        list of dict
            List of security group dictionaries with keys:
            - id : str - Security group ID (e.g., 'sg-123abc')
            - name : str - Security group name
            - description : str - Description
            - vpc_id : str - VPC ID or 'N/A' for EC2-Classic
            - is_default : bool - True if this is a default VPC SG
            - tags : dict - Tag key-value pairs

        Raises
        ------
        ResourceFetchError
            If unable to fetch security groups from AWS.

        Example
        -------
        >>> sgs = scanner.get_all_resources()
        >>> for sg in sgs:
        ...     print(f"{sg['id']}: {sg['name']}")
        """
        security_groups: List[Dict[str, Any]] = []
        paginator = self.ec2_client.get_paginator("describe_security_groups")

        logger.debug(f"Fetching all security groups in {self.region}")

        for page in paginator.paginate():
            for sg in page["SecurityGroups"]:
                security_groups.append(
                    {
                        "id": sg["GroupId"],
                        "name": sg["GroupName"],
                        "description": sg.get("Description", ""),
                        "vpc_id": sg.get("VpcId", "N/A"),
                        "is_default": sg["GroupName"] == "default",
                        "tags": {
                            tag["Key"]: tag["Value"]
                            for tag in sg.get("Tags", [])
                        },
                    }
                )

        logger.debug(f"Found {len(security_groups)} security groups in {self.region}")
        return security_groups

    def get_resources_in_use(self) -> Set[str]:
        """
        Get security group IDs that are currently in use.

        Aggregates usage information from multiple AWS services to build
        a comprehensive set of security groups that are actively in use.

        Returns
        -------
        set of str
            Security group IDs that are in use.

        Notes
        -----
        This method checks multiple sources in parallel-safe manner.
        Individual source failures are logged but don't prevent
        checking other sources.

        Example
        -------
        >>> used_ids = scanner.get_resources_in_use()
        >>> print(f"{len(used_ids)} security groups are in use")
        """
        used_sgs: Set[str] = set()

        # Collect SGs from all sources
        sources = [
            ("EC2 instances", self._get_sgs_from_ec2_instances),
            ("Network interfaces", self._get_sgs_from_enis),
            ("RDS instances", self._get_sgs_from_rds),
            ("Classic ELBs", self._get_sgs_from_classic_elb),
            ("ALB/NLB", self._get_sgs_from_elbv2),
            ("SG references", self._get_sgs_referenced_by_other_sgs),
        ]

        for source_name, fetch_func in sources:
            try:
                sgs = fetch_func()
                used_sgs.update(sgs)
                logger.debug(f"Found {len(sgs)} SGs from {source_name}")
            except Exception as e:
                logger.warning(f"Failed to get SGs from {source_name}: {e}")

        # Add default SGs to used set if excluding them
        if self.exclude_default:
            default_sgs = self._get_default_security_groups()
            used_sgs.update(default_sgs)
            logger.debug(f"Marked {len(default_sgs)} default SGs as used")

        return used_sgs

    def get_unused_resources(self) -> List[Dict[str, Any]]:
        """
        Find security groups that are not in use.

        Overrides parent method to add additional filtering for
        default security groups when configured.

        Returns
        -------
        list of dict
            List of unused security group dictionaries.

        Example
        -------
        >>> unused = scanner.get_unused_resources()
        >>> for sg in unused:
        ...     print(f"Unused: {sg['id']} ({sg['name']})")
        """
        all_sgs = self.get_all_resources()
        used_ids = self.get_resources_in_use()

        unused: List[Dict[str, Any]] = []
        for sg in all_sgs:
            sg_id = sg.get("id")
            if sg_id and sg_id not in used_ids:
                # Double-check default SG exclusion
                if self.exclude_default and sg.get("is_default", False):
                    continue
                unused.append(sg)

        return unused

    # =========================================================================
    # Private Methods: Service-Specific SG Detection
    # =========================================================================

    def _get_sgs_from_ec2_instances(self) -> Set[str]:
        """
        Get security groups attached to EC2 instances.

        Returns
        -------
        set of str
            Security group IDs attached to EC2 instances.
        """
        sg_ids: Set[str] = set()
        paginator = self.ec2_client.get_paginator("describe_instances")

        try:
            for page in paginator.paginate():
                for reservation in page["Reservations"]:
                    for instance in reservation["Instances"]:
                        for sg in instance.get("SecurityGroups", []):
                            sg_ids.add(sg["GroupId"])
        except ClientError as e:
            logger.warning(f"Error fetching EC2 instances: {e}")

        return sg_ids

    def _get_sgs_from_enis(self) -> Set[str]:
        """
        Get security groups attached to Elastic Network Interfaces.

        ENIs provide coverage for many AWS services including:
        - Lambda functions (VPC-enabled)
        - ECS tasks (awsvpc network mode)
        - ElastiCache clusters
        - Elasticsearch/OpenSearch domains
        - VPC endpoints
        - NAT Gateways
        - Transit Gateway attachments
        - And many more...

        Returns
        -------
        set of str
            Security group IDs attached to ENIs.
        """
        sg_ids: Set[str] = set()
        paginator = self.ec2_client.get_paginator("describe_network_interfaces")

        try:
            for page in paginator.paginate():
                for eni in page["NetworkInterfaces"]:
                    for sg in eni.get("Groups", []):
                        sg_ids.add(sg["GroupId"])
        except ClientError as e:
            logger.warning(f"Error fetching ENIs: {e}")

        return sg_ids

    def _get_sgs_from_rds(self) -> Set[str]:
        """
        Get security groups attached to RDS database instances.

        Returns
        -------
        set of str
            Security group IDs attached to RDS instances.
        """
        sg_ids: Set[str] = set()
        paginator = self.rds_client.get_paginator("describe_db_instances")

        try:
            for page in paginator.paginate():
                for db_instance in page["DBInstances"]:
                    for sg in db_instance.get("VpcSecurityGroups", []):
                        sg_ids.add(sg["VpcSecurityGroupId"])
        except ClientError as e:
            logger.warning(f"Error fetching RDS instances: {e}")

        return sg_ids

    def _get_sgs_from_classic_elb(self) -> Set[str]:
        """
        Get security groups attached to Classic Load Balancers.

        Returns
        -------
        set of str
            Security group IDs attached to Classic ELBs.
        """
        sg_ids: Set[str] = set()
        paginator = self.elb_client.get_paginator("describe_load_balancers")

        try:
            for page in paginator.paginate():
                for elb in page["LoadBalancerDescriptions"]:
                    for sg_id in elb.get("SecurityGroups", []):
                        sg_ids.add(sg_id)
        except ClientError as e:
            logger.warning(f"Error fetching Classic ELBs: {e}")

        return sg_ids

    def _get_sgs_from_elbv2(self) -> Set[str]:
        """
        Get security groups attached to Application/Network Load Balancers.

        Returns
        -------
        set of str
            Security group IDs attached to ALBs and NLBs.
        """
        sg_ids: Set[str] = set()
        paginator = self.elbv2_client.get_paginator("describe_load_balancers")

        try:
            for page in paginator.paginate():
                for lb in page["LoadBalancers"]:
                    for sg_id in lb.get("SecurityGroups", []):
                        sg_ids.add(sg_id)
        except ClientError as e:
            logger.warning(f"Error fetching ALB/NLB: {e}")

        return sg_ids

    def _get_sgs_referenced_by_other_sgs(self) -> Set[str]:
        """
        Get security groups referenced by other security group rules.

        When a security group is referenced as a source/destination in
        another security group's rules, it's considered in use because
        deleting it would break those rules.

        Returns
        -------
        set of str
            Security group IDs referenced in other SGs' rules.
        """
        referenced_sgs: Set[str] = set()
        paginator = self.ec2_client.get_paginator("describe_security_groups")

        try:
            for page in paginator.paginate():
                for sg in page["SecurityGroups"]:
                    # Check inbound rules
                    for rule in sg.get("IpPermissions", []):
                        for pair in rule.get("UserIdGroupPairs", []):
                            if "GroupId" in pair:
                                referenced_sgs.add(pair["GroupId"])

                    # Check outbound rules
                    for rule in sg.get("IpPermissionsEgress", []):
                        for pair in rule.get("UserIdGroupPairs", []):
                            if "GroupId" in pair:
                                referenced_sgs.add(pair["GroupId"])
        except ClientError as e:
            logger.warning(f"Error fetching SG references: {e}")

        return referenced_sgs

    def _get_default_security_groups(self) -> Set[str]:
        """
        Get all default VPC security group IDs.

        Default security groups cannot be deleted and are typically
        not useful to report as "unused".

        Returns
        -------
        set of str
            Security group IDs of default VPC security groups.
        """
        default_sgs: Set[str] = set()
        paginator = self.ec2_client.get_paginator("describe_security_groups")

        try:
            for page in paginator.paginate(
                Filters=[{"Name": "group-name", "Values": ["default"]}]
            ):
                for sg in page["SecurityGroups"]:
                    default_sgs.add(sg["GroupId"])
        except ClientError as e:
            logger.warning(f"Error fetching default SGs: {e}")

        return default_sgs

    # =========================================================================
    # String Representation
    # =========================================================================

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"SecurityGroupScanner("
            f"region='{self.region}', "
            f"exclude_default={self.exclude_default})"
        )
