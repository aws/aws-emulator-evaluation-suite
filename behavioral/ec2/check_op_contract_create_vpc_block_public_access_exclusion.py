"""op-contract-create-vpc-block-public-access-exclusion."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-create-vpc-block-public-access-exclusion"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateVpcBlockPublicAccessExclusion creates an allow-egress exclusion for a subnet, naming it by
    ResourceArn, that reaches create-complete; a deleted subnet ID fails with InvalidSubnetID.NotFound and
    its exact message."""
    ec2 = ctx.client("ec2")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    vpc_id, subnet_id, az = _create_vpc_and_subnet(ctx)
    subnet_arn = f"arn:aws:ec2:{ctx.region}:{account_id}:subnet/{subnet_id}"

    # --- error boundary: subnet that doesn't exist ---
    # A made-up subnet ID can fail the format check as InvalidSubnetID.Malformed, so use the ID of a
    # subnet created and deleted here, which is well-formed and absent.
    missing_subnet_id = _make_missing_subnet_id(ctx, vpc_id, az)
    code, message = _error(
        lambda: ec2.create_vpc_block_public_access_exclusion(
            SubnetId=missing_subnet_id, InternetGatewayExclusionMode="allow-egress"
        )
    )
    assert code == "InvalidSubnetID.NotFound", f"unexpected code: {code}"
    assert message == f"The subnet ID '{missing_subnet_id}' does not exist", message

    # --- success path ---
    resp = ec2.create_vpc_block_public_access_exclusion(
        SubnetId=subnet_id,
        InternetGatewayExclusionMode="allow-egress",
        TagSpecifications=_tag_spec(ctx, "vpc-block-public-access-exclusion", "bpa-excl"),
    )
    excl = resp["VpcBlockPublicAccessExclusion"]
    excl_id = excl["ExclusionId"]
    ctx.on_cleanup(lambda: _delete_exclusion(ctx, excl_id))
    # The exclusion identifies its target resource by ARN (there's no "SubnetId" member
    # on the response object), not by the raw id passed in the request.
    assert excl["ResourceArn"] == subnet_arn, f"expected ResourceArn {subnet_arn}, got {excl['ResourceArn']}"
    assert excl["InternetGatewayExclusionMode"] == "allow-egress", (
        f"expected mode allow-egress, got {excl['InternetGatewayExclusionMode']}"
    )
    # BlockPublicAccessExclusionState uses "create-complete" (not "created") as the terminal
    # success value.
    assert excl["State"] in ("create-in-progress", "create-complete"), excl["State"]

    # Real AWS can take several minutes to settle a new exclusion out of
    # "create-in-progress" -- 90s is not a reliably sufficient bound.
    final_state = _poll_until(
        lambda: ec2.describe_vpc_block_public_access_exclusions(ExclusionIds=[excl_id])[
            "VpcBlockPublicAccessExclusions"
        ][0]["State"],
        lambda s: s in ("create-complete", "create-failed"),
        timeout_s=600.0,
        interval_s=10.0,
    )
    assert final_state == "create-complete", f"exclusion ended in {final_state}"


# ===== helpers =====

def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its error code and message. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float = 120.0, interval_s: float = 3.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _tag_spec(ctx, resource_type: str, prefix: str) -> list[dict]:
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}]}]


def _create_vpc_and_subnet(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.77.0.0/16", TagSpecifications=_tag_spec(ctx, "vpc", "bpa-vpc"))["Vpc"][
        "VpcId"
    ]
    ctx.on_cleanup(lambda: _delete_vpc(ctx, vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.77.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=_tag_spec(ctx, "subnet", "bpa-subnet"),
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_subnet(ctx, subnet_id))
    return vpc_id, subnet_id, az


def _make_missing_subnet_id(ctx, vpc_id: str, az: str) -> str:
    from botocore.exceptions import ClientError

    ec2 = ctx.client("ec2")
    tmp_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.77.99.0/24",
        AvailabilityZone=az,
        TagSpecifications=_tag_spec(ctx, "subnet", "bpa-tmp-subnet"),
    )["Subnet"]["SubnetId"]
    ec2.delete_subnet(SubnetId=tmp_id)

    def _gone() -> bool:
        try:
            ec2.describe_subnets(SubnetIds=[tmp_id])
            return False
        except ClientError as err:
            return err.response["Error"]["Code"] == "InvalidSubnetID.NotFound"

    _poll_until(lambda: _gone(), lambda gone: gone, timeout_s=60.0)
    return tmp_id


def _delete_exclusion(ctx, excl_id: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        ec2.delete_vpc_block_public_access_exclusion(ExclusionId=excl_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVpcBlockPublicAccessExclusionId.NotFound":
            raise
        return
    try:
        _poll_until(
            lambda: ec2.describe_vpc_block_public_access_exclusions(ExclusionIds=[excl_id])[
                "VpcBlockPublicAccessExclusions"
            ][0]["State"],
            lambda s: s in ("delete-complete", "delete-failed"),
            # 600 s plus the network teardown's 240 s stays inside the suite's 900 s cleanup budget.
            timeout_s=600.0,
            interval_s=2.0,
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVpcBlockPublicAccessExclusionId.NotFound":
            raise


def _delete_subnet(ctx, subnet_id: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidNetworkInterfaceID.NotFound":
            raise


def _delete_vpc(ctx, vpc_id: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        _delete_net(ec2, "delete_vpc", VpcId=vpc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidNetworkInterfaceID.NotFound":
            raise


# AWS-managed ENIs leave a VPC asynchronously after their owner's delete returns, so DeleteSubnet,
# DeleteSecurityGroup and DeleteVpc can fail with DependencyViolation: wait for the ENIs to go,
# retry inside the same window, and raise naming any ENI still attached.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    # The exclusion teardown takes most of the 900 s cleanup budget, so the network window is
    # capped here rather than at _NET_TEARDOWN_S.
    budget = min(_NET_TEARDOWN_S, 240.0)
    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + budget)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(2)
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
                        f"{op}({ident}): DependencyViolation after {budget}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(2)


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
