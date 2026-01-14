"""
Scanner for AWS Security Groups.

Identifies unused security groups by checking if they are attached to:
- EC2 instances
- Elastic Network Interfaces (ENIs)
- RDS instances
- Load Balancers (Classic, ALB, NLB)
- Referenced by other security groups
"""

from typing import Any, Dict, List, Set

from botocore.exceptions import ClientError

from ..core.base_scanner import BaseScanner


class SecurityGroupScanner(BaseScanner):
    """
    Scanner to find unused security groups in an AWS region.

    A security group is considered "unused" if it is:
    1. Not attached to any EC2 instance
    2. Not attached to any ENI (which covers Lambda, ECS, etc.)
    3. Not attached to any RDS instance
    4. Not attached to any Load Balancer
    5. Not referenced by another security group's rules
    6. Not the default VPC security group
    """

    def __init__(self, aws_client, exclude_default: bool = True):
        """
        Initialize the security group scanner.

        Args:
            aws_client: Instance of AWSClient
            exclude_default: If True, exclude default VPC security groups from results
        """
        super().__init__(aws_client)
        self.exclude_default = exclude_default
        self._ec2_client = None
        self._rds_client = None
        self._elb_client = None
        self._elbv2_client = None

    @property
    def ec2_client(self):
        """Lazy load EC2 client."""
        if self._ec2_client is None:
            self._ec2_client = self.aws_client.get_ec2_client()
        return self._ec2_client

    @property
    def rds_client(self):
        """Lazy load RDS client."""
        if self._rds_client is None:
            self._rds_client = self.aws_client.get_rds_client()
        return self._rds_client

    @property
    def elb_client(self):
        """Lazy load Classic ELB client."""
        if self._elb_client is None:
            self._elb_client = self.aws_client.get_elb_client()
        return self._elb_client

    @property
    def elbv2_client(self):
        """Lazy load ALB/NLB client."""
        if self._elbv2_client is None:
            self._elbv2_client = self.aws_client.get_elbv2_client()
        return self._elbv2_client

    def get_resource_type(self) -> str:
        """Return the resource type identifier."""
        return "security_group"

    def get_all_resources(self) -> List[Dict[str, Any]]:
        """
        Fetch all security groups in the region.

        Returns:
            List of security group dictionaries
        """
        security_groups = []
        paginator = self.ec2_client.get_paginator("describe_security_groups")

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
                            tag["Key"]: tag["Value"] for tag in sg.get("Tags", [])
                        },
                    }
                )

        return security_groups

    def get_resources_in_use(self) -> Set[str]:
        """
        Get all security group IDs that are currently in use.

        Returns:
            Set of security group IDs that are in use
        """
        used_sgs: Set[str] = set()

        # Get SGs from EC2 instances
        used_sgs.update(self._get_sgs_from_ec2_instances())

        # Get SGs from ENIs (covers Lambda, ECS, etc.)
        used_sgs.update(self._get_sgs_from_enis())

        # Get SGs from RDS instances
        used_sgs.update(self._get_sgs_from_rds())

        # Get SGs from Classic ELBs
        used_sgs.update(self._get_sgs_from_classic_elb())

        # Get SGs from ALB/NLB
        used_sgs.update(self._get_sgs_from_elbv2())

        # Get SGs referenced by other security groups
        used_sgs.update(self._get_sgs_referenced_by_other_sgs())

        # If excluding default, add them to used set so they don't appear as unused
        if self.exclude_default:
            used_sgs.update(self._get_default_security_groups())

        return used_sgs

    def _get_sgs_from_ec2_instances(self) -> Set[str]:
        """Get security groups attached to EC2 instances."""
        sg_ids: Set[str] = set()
        paginator = self.ec2_client.get_paginator("describe_instances")

        try:
            for page in paginator.paginate():
                for reservation in page["Reservations"]:
                    for instance in reservation["Instances"]:
                        for sg in instance.get("SecurityGroups", []):
                            sg_ids.add(sg["GroupId"])
        except ClientError as e:
            # Log but don't fail - we'll still check other sources
            pass

        return sg_ids

    def _get_sgs_from_enis(self) -> Set[str]:
        """
        Get security groups attached to Elastic Network Interfaces.

        This covers many services including:
        - Lambda functions
        - ECS tasks
        - ElastiCache
        - Elasticsearch
        - VPC endpoints
        - NAT Gateways
        - etc.
        """
        sg_ids: Set[str] = set()
        paginator = self.ec2_client.get_paginator("describe_network_interfaces")

        try:
            for page in paginator.paginate():
                for eni in page["NetworkInterfaces"]:
                    for sg in eni.get("Groups", []):
                        sg_ids.add(sg["GroupId"])
        except ClientError as e:
            pass

        return sg_ids

    def _get_sgs_from_rds(self) -> Set[str]:
        """Get security groups attached to RDS instances."""
        sg_ids: Set[str] = set()
        paginator = self.rds_client.get_paginator("describe_db_instances")

        try:
            for page in paginator.paginate():
                for db_instance in page["DBInstances"]:
                    for sg in db_instance.get("VpcSecurityGroups", []):
                        sg_ids.add(sg["VpcSecurityGroupId"])
        except ClientError as e:
            pass

        return sg_ids

    def _get_sgs_from_classic_elb(self) -> Set[str]:
        """Get security groups attached to Classic Load Balancers."""
        sg_ids: Set[str] = set()
        paginator = self.elb_client.get_paginator("describe_load_balancers")

        try:
            for page in paginator.paginate():
                for elb in page["LoadBalancerDescriptions"]:
                    for sg_id in elb.get("SecurityGroups", []):
                        sg_ids.add(sg_id)
        except ClientError as e:
            pass

        return sg_ids

    def _get_sgs_from_elbv2(self) -> Set[str]:
        """Get security groups attached to Application/Network Load Balancers."""
        sg_ids: Set[str] = set()
        paginator = self.elbv2_client.get_paginator("describe_load_balancers")

        try:
            for page in paginator.paginate():
                for lb in page["LoadBalancers"]:
                    for sg_id in lb.get("SecurityGroups", []):
                        sg_ids.add(sg_id)
        except ClientError as e:
            pass

        return sg_ids

    def _get_sgs_referenced_by_other_sgs(self) -> Set[str]:
        """
        Get security groups that are referenced by other security group rules.

        A security group can reference another security group in its
        inbound or outbound rules, which means the referenced SG is in use.
        """
        referenced_sgs: Set[str] = set()
        paginator = self.ec2_client.get_paginator("describe_security_groups")

        try:
            for page in paginator.paginate():
                for sg in page["SecurityGroups"]:
                    # Check inbound rules
                    for rule in sg.get("IpPermissions", []):
                        for user_id_group_pair in rule.get("UserIdGroupPairs", []):
                            if "GroupId" in user_id_group_pair:
                                referenced_sgs.add(user_id_group_pair["GroupId"])

                    # Check outbound rules
                    for rule in sg.get("IpPermissionsEgress", []):
                        for user_id_group_pair in rule.get("UserIdGroupPairs", []):
                            if "GroupId" in user_id_group_pair:
                                referenced_sgs.add(user_id_group_pair["GroupId"])
        except ClientError as e:
            pass

        return referenced_sgs

    def _get_default_security_groups(self) -> Set[str]:
        """Get all default VPC security group IDs."""
        default_sgs: Set[str] = set()
        paginator = self.ec2_client.get_paginator("describe_security_groups")

        try:
            for page in paginator.paginate(
                Filters=[{"Name": "group-name", "Values": ["default"]}]
            ):
                for sg in page["SecurityGroups"]:
                    default_sgs.add(sg["GroupId"])
        except ClientError as e:
            pass

        return default_sgs

    def get_unused_resources(self) -> List[Dict[str, Any]]:
        """
        Find security groups that are not in use.

        Override parent method to add additional filtering logic.

        Returns:
            List of unused security group dictionaries
        """
        all_sgs = self.get_all_resources()
        used_ids = self.get_resources_in_use()

        unused = []
        for sg in all_sgs:
            sg_id = sg.get("id")
            if sg_id and sg_id not in used_ids:
                # Skip default security groups if configured
                if self.exclude_default and sg.get("is_default", False):
                    continue
                unused.append(sg)

        return unused
