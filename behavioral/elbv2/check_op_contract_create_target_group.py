"""op-contract-create-target-group."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-create-target-group"
GROUP = "error-semantics"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTargetGroup returns the requested config with correct defaults, persists it (verified
    through an independent DescribeTargetGroups read), and rejects the name being reused with a
    different configuration until the original is removed."""
    vpc_id, _ = _default_vpc_and_subnets(ctx)
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-tg-")
    resource_tags = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}]

    resp = elbv2.create_target_group(
        Name=name,
        Protocol="HTTP",
        Port=8080,
        VpcId=vpc_id,
        TargetType="instance",
        HealthCheckPath="/healthz",
        Tags=resource_tags,
    )
    tg = resp["TargetGroups"][0]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg["TargetGroupArn"]))

    assert tg["TargetGroupName"] == name
    assert tg["Protocol"] == "HTTP"
    assert tg["Port"] == 8080
    assert tg["VpcId"] == vpc_id
    assert tg["TargetType"] == "instance"
    assert tg["HealthCheckPath"] == "/healthz"
    # Documented defaults for an HTTP target group's health check.
    assert tg["HealthCheckIntervalSeconds"] == 30
    assert tg["HealthyThresholdCount"] == 5
    assert tg["TargetGroupArn"].startswith("arn:aws:elasticloadbalancing:")

    # Independent read: the create response is not an echo. DescribeTargetGroups, a different
    # operation, must report the same persisted configuration.
    described = elbv2.describe_target_groups(TargetGroupArns=[tg["TargetGroupArn"]])["TargetGroups"][0]
    assert described["TargetGroupName"] == name, described
    assert described["Port"] == 8080, described
    assert described["HealthCheckPath"] == "/healthz", described

    # Positive control already above (the create succeeded). Break exactly one thing: reuse the
    # name with a different port.
    code, message = _error(
        lambda: elbv2.create_target_group(
            Name=name, Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="instance"
        )
    )
    # Real AWS's ELBv2 API returns the error type WITHOUT the "Exception" suffix on the wire
    # (unlike the shape name used by the botocore model / docs).
    assert code == "DuplicateTargetGroupName", f"expected duplicate-name error, got {code}"
    expected = f"A target group with the same name '{name}' exists, but with different settings"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the rejected call did not create a second target group under this name.
    by_name = elbv2.describe_target_groups(Names=[name])["TargetGroups"]
    assert len(by_name) == 1 and by_name[0]["TargetGroupArn"] == tg["TargetGroupArn"], by_name

    # Restore: freeing the name lets the identical, previously-rejected call succeed.
    elbv2.delete_target_group(TargetGroupArn=tg["TargetGroupArn"])
    resp2 = elbv2.create_target_group(
        Name=name, Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="instance", Tags=resource_tags
    )
    tg = resp2["TargetGroups"][0]

    # Terminal assertion: an independent read confirms the restored target group persisted with
    # the once-rejected configuration, not just the create call's own echo.
    restored = elbv2.describe_target_groups(TargetGroupArns=[tg["TargetGroupArn"]])["TargetGroups"][0]
    assert restored["TargetGroupName"] == name, restored
    assert restored["Port"] == 80, restored


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _default_vpc_and_subnets(ctx):

    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    return vpc_id, list(by_az.values())



def _delete_target_group_when_free(elbv2, arn, timeout_s=600.0, interval_s=10.0):
    """Delete a target group once no listener or deleting load balancer still uses it (ResourceInUse)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            elbv2.delete_target_group(TargetGroupArn=arn)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "TargetGroupNotFound":
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
