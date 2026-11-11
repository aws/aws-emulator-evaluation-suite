"""``ctx.network(region)``: one network per check and region, shaped like a default VPC.

A check that needs a VPC without making networking its subject places its resources in this
network instead of the account's default VPC, which an account may not have. The network is a
VPC with DNS support and hostnames, an internet gateway, a default route to it, and one public
subnet per availability zone. The first ``ctx.network(region)`` creates it, every later one
reuses it, and the check's teardown deletes it. A check may add its own tagged, uniquely named
resources inside it (VPC endpoints, subnets, route tables, security groups) and deletes them in
its teardown, treating not-found as deleted; it never changes a resource of the network (the VPC's
attributes and CIDRs, its subnets' settings, its route tables' routes, the gateway attachment, the
default security group) or the account's default VPC.
"""

import logging
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

#: The tag every created network component carries; its value names the owner.
NETWORK_TAG = "fidelity-tests-runner:network"
#: The default VPC's CIDR and per-AZ subnet size, so addresses look like an account default.
_CIDR = "172.31.0.0/16"
_SUBNET_PREFIX = 20
#: How long a teardown retries a component the emulator still holds.
TEARDOWN_TIMEOUT_S = 30.0


@dataclass(frozen=True)
class Network:
    """The ids a check places resources with; ``subnets`` maps availability zone to subnet id."""

    vpc_id: str
    cidr: str
    subnets: dict[str, str]
    security_group_id: str
    region: str = ""

    @property
    def subnet_ids(self) -> list[str]:
        """Every subnet id, in availability-zone order."""
        return [self.subnets[az] for az in sorted(self.subnets)]

    @property
    def availability_zones(self) -> list[str]:
        return sorted(self.subnets)


def _subnet_cidrs(count: int) -> list[str]:
    """``count`` consecutive /20 blocks of the VPC CIDR, as a default VPC numbers them."""
    if count > 2 ** (_SUBNET_PREFIX - 16):
        raise ValueError(f"{count} availability zones do not fit {_CIDR} in /{_SUBNET_PREFIX}s")
    step = 2 ** (32 - _SUBNET_PREFIX)
    return [f"172.31.{(i * step) >> 8}.0/{_SUBNET_PREFIX}" for i in range(count)]


def _tags(owner: str, name: str) -> list[dict[str, str]]:
    return [{"Key": "Name", "Value": name}, {"Key": NETWORK_TAG, "Value": owner}]


def _zones(ec2: Any) -> list[str]:
    """Standard availability zones a default VPC has a subnet in: no local or wavelength zones."""
    zones = ec2.describe_availability_zones()["AvailabilityZones"]
    return sorted(
        z["ZoneName"]
        for z in zones
        if z.get("State", "available") == "available"
        and z.get("ZoneType", "availability-zone") == "availability-zone"
        and z.get("OptInStatus", "opt-in-not-required") == "opt-in-not-required"
    )


def create_network(ec2: Any, owner: str, region: str = "") -> tuple[Network, dict[str, Any]]:
    """Create a default-VPC-shaped network tagged ``NETWORK_TAG=owner``; undo it if a step fails.

    Returns the network and the ids :func:`delete_network` deletes.
    """
    name = f"sim2real-net-{uuid.uuid4().hex[:8]}"
    created: dict[str, Any] = {"subnets": []}
    try:
        vpc = ec2.create_vpc(
            CidrBlock=_CIDR,
            TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags(owner, name)}],
        )["Vpc"]
        created["vpc_id"] = vpc_id = vpc["VpcId"]
        ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id])
        ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
        ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
        igw = ec2.create_internet_gateway(
            TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _tags(owner, name)}]
        )["InternetGateway"]["InternetGatewayId"]
        created["igw_id"] = igw
        ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc_id)
        main = ec2.describe_route_tables(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "association.main", "Values": ["true"]},
            ]
        )["RouteTables"][0]["RouteTableId"]
        ec2.create_route(RouteTableId=main, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
        zones = _zones(ec2)
        subnets: dict[str, str] = {}
        for az, cidr in zip(zones, _subnet_cidrs(len(zones)), strict=True):
            subnet = ec2.create_subnet(
                VpcId=vpc_id,
                CidrBlock=cidr,
                AvailabilityZone=az,
                TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags(owner, name)}],
            )["Subnet"]["SubnetId"]
            created["subnets"].append(subnet)
            ec2.modify_subnet_attribute(SubnetId=subnet, MapPublicIpOnLaunch={"Value": True})
            subnets[az] = subnet
        sg = ec2.describe_security_groups(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "group-name", "Values": ["default"]},
            ]
        )["SecurityGroups"][0]["GroupId"]
    except Exception:
        try:
            delete_network(ec2, created, timeout_s=TEARDOWN_TIMEOUT_S)
        except Exception:  # the creation failure is the one to report
            logger.warning("could not undo a partial network %s", created, exc_info=True)
        raise
    network = Network(
        vpc_id=vpc_id, cidr=_CIDR, subnets=subnets, security_group_id=sg, region=region
    )
    return network, created


def _retrying(fn: Callable[[], Any], deadline: float) -> None:
    """``fn()`` until it stops answering DependencyViolation or the deadline passes."""
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code.endswith("NotFound") or code == "Gateway.NotAttached":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
        time.sleep(10.0)


def delete_network(
    ec2: Any, parts: dict[str, Any], *, timeout_s: float = TEARDOWN_TIMEOUT_S
) -> None:
    """Delete what :func:`create_network` created: subnets, internet gateway, VPC.

    Retries what the emulator still holds; ``parts`` may be a partial creation.
    """
    deadline = time.monotonic() + timeout_s
    vpc = parts.get("vpc_id")
    for subnet in parts.get("subnets", []):
        _retrying(lambda s=subnet: ec2.delete_subnet(SubnetId=s), deadline)
    if igw := parts.get("igw_id"):
        if vpc:
            _retrying(
                lambda: ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc), deadline
            )
        _retrying(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw), deadline)
    if vpc:
        _retrying(lambda: ec2.delete_vpc(VpcId=vpc), deadline)


class Networks:
    """A check's networks, one per region, created on first use and deleted by ``teardown``.

    A failed creation is remembered, so every later call in that region fails the same way.
    """

    def __init__(self) -> None:
        self.owner = f"run-{uuid.uuid4().hex[:12]}"
        self._created: dict[str, tuple[Network, dict[str, Any], Callable[[], Any]]] = {}
        self._errors: dict[str, BaseException] = {}
        self._lock = threading.Lock()

    def get(self, region: str, ec2_factory: Callable[[], Any]) -> Network:
        """The network in ``region``, created on first use; a failed creation fails every call."""
        with self._lock:
            if region in self._created:
                return self._created[region][0]
            if region in self._errors:
                raise RuntimeError(
                    f"the shared network could not be created: {self._errors[region]}"
                )
            try:
                network, parts = create_network(ec2_factory(), self.owner, region)
            except Exception as exc:
                self._errors[region] = exc
                raise
            self._created[region] = (network, parts, ec2_factory)
            return network

    def teardown(self) -> list[str]:
        """Delete every network created here; return one message per failure."""
        failures = []
        with self._lock:
            for region, (network, parts, ec2_factory) in list(self._created.items()):
                try:
                    delete_network(ec2_factory(), parts, timeout_s=TEARDOWN_TIMEOUT_S)
                except Exception as exc:  # report every region's failure
                    failures.append(f"{region} {network.vpc_id}: {type(exc).__name__}: {exc}")
                self._created.pop(region)
        return failures
