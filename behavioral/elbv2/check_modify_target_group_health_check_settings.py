"""modify-target-group-health-check-settings."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "modify-target-group-health-check-settings"
GROUP = "error-semantics"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyTargetGroup updates health-check settings (success path) and rejects a TCP
    health-check protocol on an HTTP target group (ValidationError)."""
    elbv2 = ctx.client("elbv2")
    vpc_id = _get_or_create_vpc(ctx)

    tg_arn = elbv2.create_target_group(
        Name=ctx.unique_name("sim2real-mtg-tg-"),
        Protocol="HTTP",
        Port=80,
        VpcId=vpc_id,
        TargetType="ip",
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-mtg-tg-"},
        ],
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn))

    # --- success path: change several health-check knobs at once ---
    modified = elbv2.modify_target_group(
        TargetGroupArn=tg_arn,
        HealthCheckIntervalSeconds=45,
        HealthCheckTimeoutSeconds=10,
        HealthyThresholdCount=7,
        UnhealthyThresholdCount=6,
        HealthCheckPath="/healthz",
        Matcher={"HttpCode": "200-299"},
    )["TargetGroups"][0]

    assert modified["TargetGroupArn"] == tg_arn, (
        f"expected ModifyTargetGroup to echo TargetGroupArn {tg_arn}, got {modified.get('TargetGroupArn')!r}"
    )
    assert modified["HealthCheckIntervalSeconds"] == 45, (
        f"expected HealthCheckIntervalSeconds=45, got {modified.get('HealthCheckIntervalSeconds')!r}"
    )
    assert modified["HealthCheckTimeoutSeconds"] == 10, (
        f"expected HealthCheckTimeoutSeconds=10, got {modified.get('HealthCheckTimeoutSeconds')!r}"
    )
    assert modified["HealthyThresholdCount"] == 7, (
        f"expected HealthyThresholdCount=7, got {modified.get('HealthyThresholdCount')!r}"
    )
    assert modified["UnhealthyThresholdCount"] == 6, (
        f"expected UnhealthyThresholdCount=6, got {modified.get('UnhealthyThresholdCount')!r}"
    )
    assert modified["HealthCheckPath"] == "/healthz", (
        f"expected HealthCheckPath=/healthz, got {modified.get('HealthCheckPath')!r}"
    )
    assert modified["Matcher"]["HttpCode"] == "200-299", (
        f"expected Matcher.HttpCode=200-299, got {modified.get('Matcher')!r}"
    )

    # confirm persisted via a fresh read
    persisted = elbv2.describe_target_groups(TargetGroupArns=[tg_arn])["TargetGroups"][0]
    assert persisted["HealthCheckIntervalSeconds"] == 45, (
        f"expected persisted HealthCheckIntervalSeconds=45, got {persisted.get('HealthCheckIntervalSeconds')!r}"
    )
    assert persisted["HealthCheckPath"] == "/healthz", (
        f"expected persisted HealthCheckPath=/healthz, got {persisted.get('HealthCheckPath')!r}"
    )

    # --- error boundary: TCP health checks are not supported for an HTTP target group ---
    code, message = _error(
        lambda: elbv2.modify_target_group(TargetGroupArn=tg_arn, HealthCheckProtocol="TCP")
    )
    assert code == "ValidationError", f"expected ValidationError, got {code!r}"
    expected = "Health check protocol 'TCP' must be one of 'HTTP, HTTPS'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # target group configuration must be unchanged after the rejected call
    unchanged = elbv2.describe_target_groups(TargetGroupArns=[tg_arn])["TargetGroups"][0]
    assert unchanged["HealthCheckProtocol"] == "HTTP", (
        f"expected HealthCheckProtocol to remain HTTP after the rejected call, got "
        f"{unchanged.get('HealthCheckProtocol')!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _get_or_create_vpc(ctx) -> str:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        return vpcs[0]["VpcId"]

    vpc_id = ec2.create_vpc(CidrBlock="10.98.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.create_tags(
        Resources=[vpc_id],
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "Name", "Value": ctx.unique_name("sim2real-mtg-vpc-")},
        ],
    )
    return vpc_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
