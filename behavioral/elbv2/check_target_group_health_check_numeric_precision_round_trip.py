"""target-group-health-check-numeric-precision-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "target-group-health-check-numeric-precision-round-trip"
GROUP = "representation"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Numeric health-check parameters (thresholds, interval, timeout) written via
    ModifyTargetGroup are read back via DescribeTargetGroups with exact integer
    precision -- no rounding, coercion to float, or clamping to a different value."""
    elbv2 = ctx.client("elbv2")
    tg_arn = elbv2.create_target_group(
        Name=ctx.unique_name("sim2real-elbv2-tg-")[:32].rstrip("-"),
        TargetType="lambda",
        HealthCheckEnabled=True,
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn))

    values = {
        "HealthCheckIntervalSeconds": 61,
        "HealthCheckTimeoutSeconds": 29,
        "HealthyThresholdCount": 6,
        "UnhealthyThresholdCount": 4,
    }
    elbv2.modify_target_group(TargetGroupArn=tg_arn, **values)

    described = elbv2.describe_target_groups(TargetGroupArns=[tg_arn])["TargetGroups"][0]
    for key, expected in values.items():
        actual = described[key]
        assert actual == expected and isinstance(actual, int), (
            f"{key}: expected exact int {expected!r}, got {actual!r} ({type(actual).__name__})"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
