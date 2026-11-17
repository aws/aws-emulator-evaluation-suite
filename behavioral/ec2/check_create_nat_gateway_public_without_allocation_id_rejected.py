"""create-nat-gateway-public-without-allocation-id-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-nat-gateway-public-without-allocation-id-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateNatGateway rejects ConnectivityType=public with no AllocationId, and the same
    subnet accepts a public NAT gateway once an AllocationId is supplied.
    """
    ec2 = ctx.client("ec2")

    vpc_id = _create_vpc_with_retry(
        ec2,
        CidrBlock="10.95.0.0/16",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.95.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[
            {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-subnet-")}]}
        ],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[
            {"ResourceType": "internet-gateway", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-igw-")}]}
        ]
    )["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(lambda: _detach_igw(ec2, igw_id, vpc_id))

    # error boundary: a public NAT gateway with no AllocationId
    code, message = _error(
        lambda: ec2.create_nat_gateway(SubnetId=subnet_id, ConnectivityType="public")
    )
    assert code == "MissingParameter", f"expected MissingParameter, got {code!r}"
    expected_message = (
        "AllocationId is required for a NAT Gateway with Connectivity Type public. "
        "Please provide the AllocationId and retry the request."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # the rejected request must not have created a NAT gateway in this subnet
    nats = ec2.describe_nat_gateways(
        Filters=[{"Name": "subnet-id", "Values": [subnet_id]}, {"Name": "state", "Values": ["pending", "available"]}]
    )["NatGateways"]
    assert nats == [], f"a rejected create must leave no NAT gateway behind, got {nats!r}"

    # positive control: the legal neighbour -- an AllocationId supplied -- succeeds
    alloc_id = ec2.allocate_address(
        Domain="vpc",
        TagSpecifications=[{"ResourceType": "elastic-ip", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["AllocationId"]
    ctx.on_cleanup(lambda: ec2.release_address(AllocationId=alloc_id))

    nat_gw_id = ec2.create_nat_gateway(
        SubnetId=subnet_id,
        AllocationId=alloc_id,
        ConnectivityType="public",
        TagSpecifications=[{"ResourceType": "natgateway", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["NatGateway"]["NatGatewayId"]
    ctx.on_cleanup(lambda: _delete_nat_gateway_and_wait(ec2, nat_gw_id))

    state = _poll_until(
        lambda: ec2.describe_nat_gateways(NatGatewayIds=[nat_gw_id])["NatGateways"][0]["State"],
        lambda s: s in ("available", "failed"),
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert state == "available", f"expected the control NAT gateway to reach available, got {state!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last saw {last!r}")


def _create_vpc_with_retry(ec2, *, timeout_s=120.0, interval_s=5.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ec2.create_vpc(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "VpcLimitExceeded" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _detach_igw(ec2, igw_id: str, vpc_id: str) -> None:
    try:
        ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("InvalidInternetGatewayID.NotFound", "Gateway.NotAttached"):
            raise


def _delete_nat_gateway_and_wait(ec2, nat_gw_id: str, timeout_s: float = 300.0) -> None:
    try:
        ec2.delete_nat_gateway(NatGatewayId=nat_gw_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NatGatewayNotFound":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            state = ec2.describe_nat_gateways(NatGatewayIds=[nat_gw_id])["NatGateways"][0]["State"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NatGatewayNotFound":
                return
            raise
        if state in ("deleted", "failed"):
            return
        time.sleep(10)
    raise AssertionError(f"NAT gateway {nat_gw_id} did not reach a deleted terminal state within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
