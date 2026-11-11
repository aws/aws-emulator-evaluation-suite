"""capacity-reservation-exceeds-limit-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "capacity-reservation-exceeds-limit-rejected"
GROUP = "e2e"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyCapacityReservation on a load balancer not enrolled for capacity reservations fails with
    OperationNotPermitted and the exact message for both an out-of-range and a 100-LCU request, and
    DescribeCapacityReservation shows neither applied."""
    elbv2 = ctx.client("elbv2")
    ec2 = ctx.client("ec2")

    net = _create_network(ctx, ec2)
    lb_arn = elbv2.create_load_balancer(
        Name=ctx.unique_name("sim2real-elbv2-")[:32].rstrip("-"),
        Subnets=net["subnet_ids"],
        SecurityGroups=[net["sg_id"]],
        Scheme="internal",
        Type="application",
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _delete_lb_and_wait(elbv2, lb_arn))
    ctx.on_cleanup(lambda: _reset_capacity_reservation(elbv2, lb_arn))
    _wait_lb_active(elbv2, lb_arn, timeout_s=180)

    huge_code, huge_message = _error_code(
        lambda: elbv2.modify_capacity_reservation(
            LoadBalancerArn=lb_arn, MinimumLoadBalancerCapacity={"CapacityUnits": 1_000_000_000}
        )
    )
    assert huge_code == "OperationNotPermitted", f"code={huge_code!r}"
    assert huge_message == _NOT_ENROLLED_MESSAGE, f"message={huge_message!r}"

    unchanged = elbv2.describe_capacity_reservation(LoadBalancerArn=lb_arn)
    assert unchanged.get("MinimumLoadBalancerCapacity") is None, (
        "rejected capacity reservation request must not have been applied"
    )

    # A normal, minimum-sized (100 LCU) request must be rejected the same, specific way
    # -- not with a different/generic error -- confirming the rejection is a stable
    # account/configuration-level gate and not a value-magnitude check that only
    # triggers for absurd inputs.
    normal_code, normal_message = _error_code(
        lambda: elbv2.modify_capacity_reservation(
            LoadBalancerArn=lb_arn, MinimumLoadBalancerCapacity={"CapacityUnits": 100}
        )
    )
    assert normal_code == huge_code, f"huge={huge_code!r} normal={normal_code!r}"
    assert normal_message == _NOT_ENROLLED_MESSAGE, f"message={normal_message!r}"

    still_unchanged = elbv2.describe_capacity_reservation(LoadBalancerArn=lb_arn)
    assert still_unchanged.get("MinimumLoadBalancerCapacity") is None, (
        "the minimum-sized capacity reservation request must not have been applied either"
    )


_NOT_ENROLLED_MESSAGE = (
    "This AWS account does not support configuring minimum load balancer capacity reservation. "
    "For more information, please contact AWS Support."
)

def _error_code(fn):
    """Return (code, message) of the ClientError ``fn`` raises; raise if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _tag_spec(resource_type: str, name: str) -> dict[str, Any]:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _create_network(ctx, ec2) -> dict[str, Any]:
    vpc_name = ctx.unique_name("sim2real-elbv2-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.81.0.0/16", TagSpecifications=[_tag_spec("vpc", vpc_name)]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones()["AvailabilityZones"]
        if z["State"] == "available"
    ][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_name = ctx.unique_name("sim2real-elbv2-subnet-")
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.81.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec("subnet", subnet_name)],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(lambda sid=sid: _retry_delete(lambda: ec2.delete_subnet(SubnetId=sid)))
    sg_name = ctx.unique_name("sim2real-elbv2-sg-")
    sg_id = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=sg_name,
        Description="sim2real elbv2 capacity limit behavioral check",
        TagSpecifications=[_tag_spec("security-group", sg_name)],
    )["GroupId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_security_group(GroupId=sg_id)))
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "sg_id": sg_id}


def _retry_delete(fn, attempts: int = 24, delay: float = 5.0) -> None:
    last: Exception | None = None
    for _ in range(attempts):
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            if code in ("DependencyViolation", "InvalidGroup.InUse", "InvalidVpcID.InUse"):
                last = exc
                time.sleep(delay)
                continue
            raise
    if last:
        raise last


def _wait_lb_active(elbv2, lb_arn: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]["State"]["Code"]
        if state == "active":
            return
        time.sleep(2)
    raise AssertionError(f"load balancer never became active, last state={state}")


def _reset_capacity_reservation(elbv2, lb_arn: str) -> None:
    try:
        elbv2.modify_capacity_reservation(LoadBalancerArn=lb_arn, ResetCapacityReservation=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
            raise


def _delete_lb_and_wait(elbv2, lb_arn: str, timeout_s: float = 180) -> None:
    try:
        elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)
    except elbv2.exceptions.LoadBalancerNotFoundException:
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])
        except elbv2.exceptions.LoadBalancerNotFoundException:
            return
        time.sleep(5)
    raise AssertionError("load balancer was not removed within timeout")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
