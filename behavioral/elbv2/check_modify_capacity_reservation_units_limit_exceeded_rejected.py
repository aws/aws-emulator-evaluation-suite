"""modify-capacity-reservation-units-limit-exceeded-rejected."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-capacity-reservation-units-limit-exceeded-rejected"
GROUP = "error-semantics"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyCapacityReservation on a load balancer not enrolled for capacity reservations fails with
    OperationNotPermitted for both an over-ceiling and a 100-LCU request with the same message, and neither
    request sets MinimumLoadBalancerCapacity."""
    elbv2 = ctx.client("elbv2")
    net = _create_vpc_with_subnets(ctx, az_count=2)
    lb_arn = _create_load_balancer(ctx, net, lb_type="application")
    _wait_lb_active(ctx, lb_arn)

    baseline = elbv2.describe_capacity_reservation(LoadBalancerArn=lb_arn)
    assert not baseline.get("MinimumLoadBalancerCapacity"), baseline

    huge_code, huge_message = _error_code_and_message(
        lambda: elbv2.modify_capacity_reservation(
            LoadBalancerArn=lb_arn,
            MinimumLoadBalancerCapacity={"CapacityUnits": 5_000_000},
        )
    )
    assert huge_code == "OperationNotPermitted", (huge_code, huge_message)
    assert "does not support configuring minimum load balancer capacity reservation" in huge_message, huge_message

    # effect-absent: the rejected, wildly-over-ceiling request must not have taken hold
    after_huge = elbv2.describe_capacity_reservation(LoadBalancerArn=lb_arn)
    assert not after_huge.get("MinimumLoadBalancerCapacity"), after_huge

    # the documented ALB floor (100 LCU) is refused the SAME way -- an account-level gate,
    # not a magnitude check that only trips for absurd values
    normal_code, normal_message = _error_code_and_message(
        lambda: elbv2.modify_capacity_reservation(
            LoadBalancerArn=lb_arn,
            MinimumLoadBalancerCapacity={"CapacityUnits": 100},
        )
    )
    assert normal_code == huge_code, (normal_code, huge_code)
    assert normal_message == huge_message, (normal_message, huge_message)

    described_after = elbv2.describe_capacity_reservation(LoadBalancerArn=lb_arn)
    assert not described_after.get("MinimumLoadBalancerCapacity"), described_after


def _error_code_and_message(fn):
    try:
        resp = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError(f"expected ModifyCapacityReservation to be rejected, but it succeeded: {resp!r}")


def _tag_spec(resource_type: str, name: str) -> dict[str, Any]:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _create_vpc_with_subnets(ctx, az_count: int = 2) -> dict[str, Any]:
    ec2 = ctx.client("ec2")
    vpc_name = ctx.unique_name("sim2real-elbv2-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.77.0.0/16", TagSpecifications=[_tag_spec("vpc", vpc_name)]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_vpc_with_retry(ec2, vpc_id))

    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][:az_count]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.77.{i}.0/24",
            AvailabilityZone=az["ZoneName"],
            TagSpecifications=[
                _tag_spec("subnet", ctx.unique_name("sim2real-elbv2-subnet-"))
            ],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_subnet_with_retry(ec2, sid))
        subnet_ids.append(subnet_id)

    sg_id = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    )["SecurityGroups"][0]["GroupId"]
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "sg_id": sg_id}


def _delete_subnet_with_retry(ec2, subnet_id: str, timeout_s: float = 180.0) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_subnet(SubnetId=subnet_id)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "DependencyViolation" or time.monotonic() > deadline:
                raise
            time.sleep(5)


def _delete_vpc_with_retry(ec2, vpc_id: str, timeout_s: float = 180.0) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_vpc(VpcId=vpc_id)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "DependencyViolation" or time.monotonic() > deadline:
                raise
            time.sleep(5)


def _create_load_balancer(ctx, net: dict[str, Any], lb_type: str = "application") -> str:
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-lb-")
    kwargs: dict[str, Any] = {
        "Name": name,
        "Subnets": net["subnet_ids"],
        "Scheme": "internal",
        "Type": lb_type,
    }
    if lb_type == "application":
        kwargs["SecurityGroups"] = [net["sg_id"]]
    lb_arn = elbv2.create_load_balancer(**kwargs)["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _delete_lb_and_wait(elbv2, lb_arn))
    return lb_arn


def _delete_lb_and_wait(elbv2, lb_arn: str, timeout_s: float = 180.0) -> None:
    try:
        elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "LoadBalancerNotFound":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])
        except ClientError as err:
            if err.response["Error"]["Code"] == "LoadBalancerNotFound":
                return
            raise
        time.sleep(5)


def _wait_lb_active(ctx, lb_arn: str, timeout_s: float = 360.0) -> None:
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        lb = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]
        code = lb["State"]["Code"]
        if code == "active":
            return
        if code == "failed":
            raise AssertionError(f"load balancer entered failed state: {lb['State']}")
        time.sleep(5)
    raise AssertionError("load balancer did not become active in time")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
