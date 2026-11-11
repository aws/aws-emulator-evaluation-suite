"""register-targets-duplicate-id-conflicting-port-rejected."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-targets-duplicate-id-conflicting-port-rejected"
GROUP = "overly-permissive"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterTargets rejects an instance ID on an "ip" target group with ValidationError and registers
    nothing, while a valid IP target on a non-default port registers. AWS documents the same ID with
    two ports in one call as supported, so the ID/TargetType mismatch is the rejected boundary."""
    elbv2 = ctx.client("elbv2")
    vpc_id, subnet_cidr = _create_vpc_with_subnet(ctx)

    tg = elbv2.create_target_group(
        Name=ctx.unique_name("sim2real-behav-tg-"),
        Protocol="HTTP",
        Port=80,
        VpcId=vpc_id,
        TargetType="ip",
    )["TargetGroups"][0]
    tg_arn = tg["TargetGroupArn"]
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn))

    bad_id = "i-0123456789abcdef0"  # an instance ID is invalid for an "ip" type target group

    def _register_bad() -> None:
        elbv2.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": bad_id, "Port": 80}])

    code, message = _error(_register_bad)
    # Empirically, real AWS rejects an instance-ID-shaped target on an "ip" type target
    # group with the generic ValidationError (a format/type mismatch caught before the
    # InvalidTarget "not in VPC / doesn't exist" semantic check runs).
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    expected = f"The IP address '{bad_id}' is not a valid IPv4 address"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: nothing was registered.
    health = elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
    assert health == [], f"expected no registered targets, got {health}"

    # Positive control: a syntactically-valid "ip" target, on a non-default port, registers.
    good_ip = subnet_cidr.replace(".0/24", ".5")
    elbv2.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": good_ip, "Port": 8080}])
    ctx.on_cleanup(
        lambda: elbv2.deregister_targets(TargetGroupArn=tg_arn, Targets=[{"Id": good_ip, "Port": 8080}])
    )
    health = elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
    assert len(health) == 1, f"expected exactly the one valid target registered, got {health}"
    assert health[0]["Target"]["Id"] == good_ip, (
        f"expected registered target Id {good_ip!r}, got {health[0]['Target']['Id']!r}"
    )
    assert health[0]["Target"]["Port"] == 8080, (
        f"expected registered target Port 8080, got {health[0]['Target']['Port']!r}"
    )



def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _create_vpc_with_subnet(ctx: Any) -> tuple[str, str]:
    ec2 = ctx.client("ec2")
    vpc = ec2.create_vpc(
        CidrBlock="10.106.0.0/16",
        TagSpecifications=[{
            "ResourceType": "vpc",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}],
        }],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    az_name = next(
        az["ZoneName"]
        for az in ec2.describe_availability_zones()["AvailabilityZones"]
        if az["State"] == "available"
    )
    subnet_cidr = "10.106.1.0/24"
    subnet = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=subnet_cidr,
        AvailabilityZone=az_name,
        TagSpecifications=[{
            "ResourceType": "subnet",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-subnet-")}],
        }],
    )["Subnet"]
    subnet_id = subnet["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    return vpc_id, subnet_cidr


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
