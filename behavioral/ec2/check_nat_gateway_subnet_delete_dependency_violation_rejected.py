"""nat-gateway-subnet-delete-dependency-violation-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "nat-gateway-subnet-delete-dependency-violation-rejected"
GROUP = "overly-permissive"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteSubnet on a subnet hosting an available NAT gateway fails with DependencyViolation
    and leaves it in place; a free sibling subnet deletes, and the busy one deletes once the NAT
    gateway reaches deleted."""
    ec2 = ctx.client("ec2")

    vpc_id = _create_vpc_with_retry(
        ec2,
        CidrBlock="10.83.0.0/16",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    # Without an attached internet gateway a NAT gateway lands in "failed" (Gateway.NotAttached).
    igw_id = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]

    def _cleanup_igw():
        _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id)
        _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id)

    ctx.on_cleanup(_cleanup_igw)
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    free_subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.83.2.0/24",
        TagSpecifications=[
            {
                "ResourceType": "subnet",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-subnet-free-")}],
            }
        ],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _cleanup_ignore_notfound(lambda: _delete_net(ec2, "delete_subnet", SubnetId=free_subnet_id)))
    resp = ec2.delete_subnet(SubnetId=free_subnet_id)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected the free subnet delete to succeed, got HTTP {resp['ResponseMetadata']['HTTPStatusCode']}"
    )
    code, message = _error(lambda: ec2.describe_subnets(SubnetIds=[free_subnet_id]))
    assert code == "InvalidSubnetID.NotFound", f"expected the free subnet gone, got {code}"
    assert message == f"The subnet ID '{free_subnet_id}' does not exist", message

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.83.1.0/24",
        TagSpecifications=[
            {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-subnet-")}]}
        ],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _cleanup_ignore_notfound(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)))

    alloc_id = ec2.allocate_address(Domain="vpc")["AllocationId"]
    ctx.on_cleanup(lambda: ec2.release_address(AllocationId=alloc_id))

    nat_id = ec2.create_nat_gateway(SubnetId=subnet_id, AllocationId=alloc_id)["NatGateway"][
        "NatGatewayId"
    ]

    def _cleanup_nat():
        _cleanup_ignore_notfound(lambda: ec2.delete_nat_gateway(NatGatewayId=nat_id))
        _poll_until(
            lambda: _nat_state(ec2, nat_id),
            lambda state: state in ("deleted", "deleting", "failed"),
            timeout_s=120,
            interval_s=5,
        )

    ctx.on_cleanup(_cleanup_nat)

    # NAT gateway provisioning can take well over 3 minutes.
    nat_state = _poll_until(
        lambda: _nat_state(ec2, nat_id),
        lambda state: state in ("available", "failed"),
        timeout_s=480,
        interval_s=10,
    )
    assert nat_state == "available", f"NAT gateway did not become available: {nat_state}"

    code, message = _error(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    assert code == "DependencyViolation", f"expected DependencyViolation, got {code}"
    assert message == f"The subnet '{subnet_id}' has dependencies and cannot be deleted.", message

    still_there = ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"]
    assert len(still_there) == 1 and still_there[0]["SubnetId"] == subnet_id, (
        f"expected subnet {subnet_id} to still exist after the refused delete, got {still_there}"
    )

    # The gateway keeps a managed ENI in the subnet until "deleted", not merely "deleting".
    ec2.delete_nat_gateway(NatGatewayId=nat_id)
    deleted_state = _poll_until(
        lambda: _nat_state(ec2, nat_id),
        lambda state: state == "deleted",
        timeout_s=180,
        interval_s=10,
    )
    assert deleted_state == "deleted", f"NAT gateway did not reach deleted: {deleted_state}"

    resp = ec2.delete_subnet(SubnetId=subnet_id)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected the delete to succeed once the NAT gateway was gone, got HTTP "
        f"{resp['ResponseMetadata']['HTTPStatusCode']}"
    )
    code, message = _error(lambda: ec2.describe_subnets(SubnetIds=[subnet_id]))
    assert code == "InvalidSubnetID.NotFound", f"expected subnet {subnet_id} gone, got {code}"
    assert message == f"The subnet ID '{subnet_id}' does not exist", message


def _error(fn):
    """Return the (code, message) of fn()'s ClientError; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _nat_state(ec2, nat_id):
    gws = ec2.describe_nat_gateways(NatGatewayIds=[nat_id])["NatGateways"]
    return gws[0]["State"] if gws else "deleted"


def _cleanup_ignore_notfound(fn):
    try:
        fn()
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code not in ("InvalidSubnetID.NotFound", "InvalidNatGatewayID.NotFound", "NatGatewayNotFound"):
            raise


def _create_vpc_with_retry(ec2, *, timeout_s=120.0, interval_s=5.0, **kwargs):
    """create_vpc, retrying VpcLimitExceeded until a slot in the per-region VPC quota frees up."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ec2.create_vpc(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "VpcLimitExceeded" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while True:
        if predicate(result):
            return result
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
        result = probe()
    raise AssertionError(f"condition not met within {timeout_s}s (last={result!r})")


# AWS-managed ENIs (e.g. a NAT gateway's) leave a subnet/VPC asynchronously after their owner is
# deleted, so an immediate delete fails with DependencyViolation. Teardown waits (bounded, one window
# shared by all of a check's network deletes) for them, then raises naming the ENIs still attached.
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
