"""get-requester-gateway-not-found."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "get-requester-gateway-not-found"
GROUP = "error-semantics"
SERVICES = ["rtbfabric"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetRequesterGateway on a well-formed but nonexistent gatewayId (a pure hex suffix, so format
    validation passes) raises ResourceNotFoundException, after the same call on a just-created
    gateway succeeds.
    """
    rtb = ctx.client("rtbfabric")
    network = _create_network(ctx)
    real_gateway_id = _create_requester_gateway(ctx, network)

    # Positive control: the real, just-created gateway is readable.
    described = rtb.get_requester_gateway(gatewayId=real_gateway_id)
    assert described["gatewayId"] == real_gateway_id, "positive control: real gateway must be readable"

    # Break exactly one thing: same id shape, but never created.
    fake_gateway_id = "rtb-gw-" + uuid.uuid4().hex[:18]
    error = _client_error(lambda: rtb.get_requester_gateway(gatewayId=fake_gateway_id))
    assert error["Code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {error['Code']}"
    expected_message = "The requested resource was not found."
    assert error["Message"] == expected_message, f"expected {expected_message!r}, got {error['Message']!r}"

    # Settle and delete the real gateway in-body, so its ENIs are gone before network teardown.
    _poll_until(
        lambda: rtb.get_requester_gateway(gatewayId=real_gateway_id)["status"],
        lambda s: s in ("ACTIVE", "ERROR"),
        timeout_s=900.0,
        interval_s=15.0,
    )
    _delete_requester_gateway_blocking(rtb, real_gateway_id)


# ===== helpers (self-contained) =====
def _create_network(ctx):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-rtbfabric-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.99.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    _poll_until(
        lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"],
        lambda s: s == "available",
        timeout_s=60.0,
        interval_s=2.0,
    )
    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.99.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    sg_id = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=name,
        Description="sim2real rtbfabric behavioral test sg",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))
    return {"vpc_id": vpc_id, "subnet_id": subnet_id, "sg_id": sg_id}


def _ensure_rtbfabric_slr(ctx) -> None:
    """AWSServiceRoleForRTBFabric must exist before CreateRequesterGateway can assume it.
    Shared, account-level, never deleted by this check."""
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="rtbfabric.amazonaws.com")
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("InvalidInput", "AlreadyExists"):
            raise


def _retry_slr_propagation(fn, timeout_s: float = 300.0, interval_s: float = 15.0):
    """Call fn, retrying while RTB Fabric cannot yet use a just-created service-linked role:
    until IAM propagates it, gateway calls answer a bare 400 "Unable to complete request".
    Any other outcome, success or a different error, is returned or raised at once."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            error = exc.response["Error"]
            unready = error.get("Code") == "400" and (error.get("Message") or "").startswith(
                "Unable to complete request."
            )
            if not unready or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _create_requester_gateway(ctx, network):
    rtb = ctx.client("rtbfabric")
    _ensure_rtbfabric_slr(ctx)
    token = ctx.unique_name("tok-")
    resp = _retry_slr_propagation(
        lambda: rtb.create_requester_gateway(
            vpcId=network["vpc_id"],
            subnetIds=[network["subnet_id"]],
            securityGroupIds=[network["sg_id"]],
            clientToken=token,
        )
    )
    gateway_id = resp["gatewayId"]
    ctx.on_cleanup(lambda: _delete_requester_gateway_blocking(rtb, gateway_id))
    return gateway_id


def _delete_requester_gateway_blocking(rtb, gateway_id, timeout_s=1200.0):
    """Delete a requester gateway and wait until it reads DELETED or not-found, so its ENIs have
    left before the network under it is torn down. DeleteRequesterGateway refuses a gateway that
    is still settling (ConflictException), so the delete is retried through that window. Safe to
    call twice: a gateway that is already gone returns at once."""
    from botocore.exceptions import ClientError

    def gone():
        try:
            return rtb.get_requester_gateway(gatewayId=gateway_id)["status"] == "DELETED"
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return True
            raise

    deadline = time.monotonic() + timeout_s
    while not gone():
        try:
            rtb.delete_requester_gateway(gatewayId=gateway_id)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("ConflictException", "ResourceNotFoundException"):
                raise
            if time.monotonic() >= deadline:
                raise
        time.sleep(15.0)
    while not gone():
        if time.monotonic() >= deadline:
            raise AssertionError(f"requester gateway {gateway_id} not deleted within {timeout_s}s")
        time.sleep(15.0)


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _client_error(fn):
    """Call fn(); return its botocore error (Code and Message). An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must fail loudly, not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation, and swallowing that leaks the VPC
# while the check passes. So wait (bounded) for the resource's ENIs to go, retry
# DependencyViolation inside the same window, and raise a final failure naming the ENIs still
# attached; every other error propagates. Teardown-only: nothing run() executes calls this, so it
# cannot change the verdict. The window is shared by all of one check's network deletes and fits
# the suite's 900 s cleanup budget.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
