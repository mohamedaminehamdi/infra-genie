"""
Elastic IP Scanner Module
=========================

Identifies unused Elastic IP addresses (EIPs) across AWS accounts.

Elastic IPs that are allocated but not associated with any resource
incur charges. This scanner helps identify those unused EIPs to
reduce unnecessary costs.

Classes
-------
EIPScanner
    Main scanner class for identifying unused Elastic IPs.

Example
-------
>>> from src.scanners import EIPScanner
>>> from src.core import AWSClient
>>>
>>> client = AWSClient(region="us-east-1")
>>> scanner = EIPScanner(client)
>>> result = scanner.scan()
>>>
>>> for eip in result.unused_resources:
...     print(f"{eip['public_ip']}: {eip['allocation_id']}")

Detection Logic
---------------
An Elastic IP is considered "unused" if:

1. **No Association** - Not associated with any EC2 instance
2. **No Network Interface** - Not attached to any network interface
3. **No NAT Gateway** - Not used by a NAT Gateway

Notes
-----
AWS charges for Elastic IPs that are:
- Allocated but not associated with a running instance
- Associated with a stopped instance
- Associated with an unattached network interface

This scanner identifies all unassociated EIPs which are the primary
source of unnecessary charges.

See Also
--------
BaseScanner : Abstract base class.
VPCScanner : Scanner for unused VPCs.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Set

from botocore.exceptions import ClientError

from src.core.base_scanner import BaseScanner

# Module logger
logger = logging.getLogger(__name__)


class EIPScanner(BaseScanner):
    """
    Scanner for identifying unused Elastic IP addresses.

    Detects Elastic IPs that are allocated but not associated with
    any EC2 instance or network interface, which incur unnecessary charges.

    Parameters
    ----------
    aws_client : AWSClient
        Instance of AWSClient for AWS API access.

    Attributes
    ----------
    region : str
        The AWS region being scanned.

    Examples
    --------
    Basic usage:

    >>> scanner = EIPScanner(client)
    >>> result = scanner.scan()
    >>> print(f"Found {result.unused_count} unused Elastic IPs")

    Getting cost information:

    >>> for eip in result.unused_resources:
    ...     print(f"IP: {eip['public_ip']}")
    ...     print(f"Allocation ID: {eip['allocation_id']}")
    ...     print(f"Domain: {eip['domain']}")

    See Also
    --------
    BaseScanner : Parent class defining the scanner interface.
    """

    def __init__(self, aws_client) -> None:
        """Initialize the EIP scanner."""
        super().__init__(aws_client)

        # Lazy-loaded service clients
        self._ec2_client = None

        logger.debug(f"Initialized EIPScanner for {self.region}")

    # =========================================================================
    # Service Client Properties (Lazy Loading)
    # =========================================================================

    @property
    def ec2_client(self):
        """Get EC2 client (lazy loaded)."""
        if self._ec2_client is None:
            self._ec2_client = self.aws_client.get_ec2_client()
        return self._ec2_client

    # =========================================================================
    # BaseScanner Abstract Method Implementations
    # =========================================================================

    def get_resource_type(self) -> str:
        """
        Get the resource type identifier.

        Returns
        -------
        str
            Always returns 'elastic_ip'.
        """
        return "elastic_ip"

    def get_all_resources(self) -> List[Dict[str, Any]]:
        """
        Fetch all Elastic IPs in the region.

        Returns
        -------
        list of dict
            List of EIP dictionaries with keys:
            - id : str - Allocation ID (e.g., 'eipalloc-123abc')
            - allocation_id : str - Same as id, for clarity
            - public_ip : str - The public IP address
            - name : str - Name from tags (or the public IP)
            - domain : str - 'vpc' or 'standard'
            - association_id : str or None - Association ID if associated
            - instance_id : str or None - Associated instance ID
            - network_interface_id : str or None - Associated ENI ID
            - private_ip : str or None - Associated private IP
            - tags : dict - Tag key-value pairs

        Raises
        ------
        ResourceFetchError
            If unable to fetch Elastic IPs from AWS.

        Example
        -------
        >>> eips = scanner.get_all_resources()
        >>> for eip in eips:
        ...     print(f"{eip['public_ip']}: {eip['allocation_id']}")
        """
        eips: List[Dict[str, Any]] = []

        logger.debug(f"Fetching all Elastic IPs in {self.region}")

        try:
            response = self.ec2_client.describe_addresses()

            for address in response.get("Addresses", []):
                # Extract name from tags
                tags = {tag["Key"]: tag["Value"] for tag in address.get("Tags", [])}
                name = tags.get("Name", address.get("PublicIp", "unnamed"))

                allocation_id = address.get("AllocationId", "N/A")

                eips.append(
                    {
                        "id": allocation_id,
                        "allocation_id": allocation_id,
                        "public_ip": address.get("PublicIp", "N/A"),
                        "name": name,
                        "domain": address.get("Domain", "vpc"),
                        "association_id": address.get("AssociationId"),
                        "instance_id": address.get("InstanceId"),
                        "network_interface_id": address.get("NetworkInterfaceId"),
                        "private_ip": address.get("PrivateIpAddress"),
                        "network_interface_owner_id": address.get("NetworkInterfaceOwnerId"),
                        "tags": tags,
                    }
                )

            logger.debug(f"Found {len(eips)} Elastic IPs in {self.region}")

        except ClientError as e:
            logger.error(f"Error fetching Elastic IPs: {e}")
            raise

        return eips

    def get_resources_in_use(self) -> Set[str]:
        """
        Get Elastic IP allocation IDs that are currently in use.

        An EIP is considered "in use" if it has an association ID,
        meaning it's attached to an instance or network interface.

        Returns
        -------
        set of str
            Allocation IDs of EIPs that are in use.

        Example
        -------
        >>> used_ids = scanner.get_resources_in_use()
        >>> print(f"{len(used_ids)} Elastic IPs are in use")
        """
        used_eips: Set[str] = set()

        # Collect EIPs from all sources
        sources = [
            ("Associated EIPs", self._get_associated_eips),
            ("NAT Gateway EIPs", self._get_nat_gateway_eips),
        ]

        for source_name, fetch_func in sources:
            try:
                eips = fetch_func()
                used_eips.update(eips)
                logger.debug(f"Found {len(eips)} EIPs from {source_name}")
            except Exception as e:
                logger.warning(f"Failed to get EIPs from {source_name}: {e}")

        return used_eips

    # =========================================================================
    # Private Methods: EIP Usage Detection
    # =========================================================================

    def _get_associated_eips(self) -> Set[str]:
        """Get EIPs that are associated with instances or ENIs."""
        associated_eips: Set[str] = set()

        try:
            response = self.ec2_client.describe_addresses()

            for address in response.get("Addresses", []):
                # If there's an association ID, it's in use
                if address.get("AssociationId"):
                    allocation_id = address.get("AllocationId")
                    if allocation_id:
                        associated_eips.add(allocation_id)

        except ClientError as e:
            logger.warning(f"Error checking EIP associations: {e}")

        return associated_eips

    def _get_nat_gateway_eips(self) -> Set[str]:
        """Get EIPs that are used by NAT Gateways."""
        nat_eips: Set[str] = set()
        paginator = self.ec2_client.get_paginator("describe_nat_gateways")

        try:
            # Only check active NAT gateways
            for page in paginator.paginate(
                Filters=[{"Name": "state", "Values": ["available", "pending"]}]
            ):
                for nat in page.get("NatGateways", []):
                    for address in nat.get("NatGatewayAddresses", []):
                        allocation_id = address.get("AllocationId")
                        if allocation_id:
                            nat_eips.add(allocation_id)

        except ClientError as e:
            logger.warning(f"Error fetching NAT Gateways: {e}")

        return nat_eips

    # =========================================================================
    # String Representation
    # =========================================================================

    def __repr__(self) -> str:
        """Return string representation."""
        return f"EIPScanner(region='{self.region}')"
