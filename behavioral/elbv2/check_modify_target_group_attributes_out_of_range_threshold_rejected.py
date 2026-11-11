"""modify-target-group-attributes-out-of-range-threshold-rejected."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-target-group-attributes-out-of-range-threshold-rejected"
GROUP = "overly-permissive"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyTargetGroup with HealthyThresholdCount=15 (outside 2-10) fails with ValidationError and
    its exact message rather than being clamped; the prior valid value is kept and a later valid
    modify still succeeds."""
    elbv2 = ctx.client("elbv2")
    vpc_id = _create_vpc(ctx)

    tg_name = ctx.unique_name("sim2real-behav-tg-")
    tg = elbv2.create_target_group(
        Name=tg_name,
        Protocol="HTTP",
        Port=80,
        VpcId=vpc_id,
        TargetType="ip",
    )["TargetGroups"][0]
    tg_arn = tg["TargetGroupArn"]
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn))
    original_threshold = tg["HealthyThresholdCount"]

    # Positive control: a valid value distinct from the default, so a no-op ModifyTargetGroup fails.
    valid_before = 5 if original_threshold != 5 else 6
    elbv2.modify_target_group(TargetGroupArn=tg_arn, HealthyThresholdCount=valid_before)
    before = elbv2.describe_target_groups(TargetGroupArns=[tg_arn])["TargetGroups"][0]
    assert before["HealthyThresholdCount"] == valid_before, (
        f"the positive control did not set HealthyThresholdCount to {valid_before}: "
        f"got {before['HealthyThresholdCount']}"
    )

    def _modify_bad() -> None:
        elbv2.modify_target_group(TargetGroupArn=tg_arn, HealthyThresholdCount=15)

    code, message = _error(_modify_bad)
    # Real AWS rejects an out-of-range HealthyThresholdCount with the generic
    # ValidationError, not InvalidConfigurationRequest.
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    expected = (
        "1 validation error detected: Value '15' at 'healthyThresholdCount' failed to satisfy "
        "constraint: Member must have value less than or equal to 10"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the threshold was not clamped/changed by the rejected call.
    unchanged = elbv2.describe_target_groups(TargetGroupArns=[tg_arn])["TargetGroups"][0]
    assert unchanged["HealthyThresholdCount"] == valid_before, (
        f"HealthyThresholdCount changed from {valid_before} to "
        f"{unchanged['HealthyThresholdCount']} despite the rejected request"
    )

    # Positive control after the rejection: a different in-range value is still
    # accepted, so the refusal did not wedge the target group.
    valid_after = 3 if valid_before != 3 else 4
    elbv2.modify_target_group(TargetGroupArn=tg_arn, HealthyThresholdCount=valid_after)
    updated = elbv2.describe_target_groups(TargetGroupArns=[tg_arn])["TargetGroups"][0]
    assert updated["HealthyThresholdCount"] == valid_after, (
        f"expected HealthyThresholdCount {valid_after} after the post-rejection modify, "
        f"got {updated['HealthyThresholdCount']}"
    )


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected success raises, so
    accepting refused input is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_vpc(ctx: Any) -> str:
    ec2 = ctx.client("ec2")
    vpc = ec2.create_vpc(
        CidrBlock="10.103.0.0/16",
        TagSpecifications=[{
            "ResourceType": "vpc",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}],
        }],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    return vpc_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
