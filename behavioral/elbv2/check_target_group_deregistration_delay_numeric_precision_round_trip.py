"""target-group-deregistration-delay-numeric-precision-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "target-group-deregistration-delay-numeric-precision-round-trip"
GROUP = "representation"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """deregistration_delay.timeout_seconds set to its documented maximum (3600) reads back from
    DescribeTargetGroupAttributes as the exact string, not reformatted or clamped."""
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")

    vpc = ec2.create_vpc(CidrBlock="10.177.0.0/16")["Vpc"]
    vpc_id = vpc["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "sim2real", "Value": "behavioral"}])

    tg = elbv2.create_target_group(
        Name=ctx.unique_name("sim2real-behav-tg-"),
        Protocol="HTTP",
        Port=80,
        VpcId=vpc_id,
        TargetType="ip",
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["TargetGroups"][0]
    tg_arn = tg["TargetGroupArn"]
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn))

    boundary_value = "3600"  # documented maximum for deregistration_delay.timeout_seconds
    elbv2.modify_target_group_attributes(
        TargetGroupArn=tg_arn,
        Attributes=[{"Key": "deregistration_delay.timeout_seconds", "Value": boundary_value}],
    )

    attrs = elbv2.describe_target_group_attributes(TargetGroupArn=tg_arn)["Attributes"]
    matches = [a for a in attrs if a["Key"] == "deregistration_delay.timeout_seconds"]
    assert len(matches) == 1, f"attribute missing from {attrs}"
    assert matches[0]["Value"] == boundary_value, (
        f"expected exact '{boundary_value}', got {matches[0]['Value']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
