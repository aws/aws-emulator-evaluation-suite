"""op-contract-describe-target-group-attributes."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-target-group-attributes"
GROUP = "error-semantics"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTargetGroupAttributes returns the documented defaults; a bogus TG ARN is rejected."""
    vpc_id = _default_or_new_vpc(ctx)
    elbv2 = ctx.client("elbv2")
    tg = _create_tg(ctx, vpc_id)

    attrs = {
        a["Key"]: a["Value"]
        for a in elbv2.describe_target_group_attributes(TargetGroupArn=tg["TargetGroupArn"])["Attributes"]
    }
    # Documented default for HTTP target groups.
    got_delay = attrs.get("deregistration_delay.timeout_seconds")
    assert got_delay == "300", f"expected deregistration_delay.timeout_seconds=300, got {got_delay!r}"
    assert "stickiness.enabled" in attrs, f"stickiness.enabled missing from Attributes: {attrs!r}"
    got_sticky = attrs.get("stickiness.enabled")
    assert got_sticky == "false", f"expected stickiness.enabled=false, got {got_sticky!r}"

    bogus_arn = tg["TargetGroupArn"][:-1] + ("0" if tg["TargetGroupArn"][-1] != "0" else "1")
    code, message = _error(lambda: elbv2.describe_target_group_attributes(TargetGroupArn=bogus_arn))
    # Real AWS's ELBv2 API returns the error type WITHOUT the "Exception" suffix on the wire
    # (unlike the shape name used by the botocore model / docs).
    assert code == "TargetGroupNotFound", f"expected not-found, got {code}"
    expected = f"Target groups '{bogus_arn}' not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to fail, but it SUCCEEDED and returned {result!r}")


def _default_or_new_vpc(ctx):
    """Adopt the shared network if the account has one; otherwise create a throwaway one.

    create_target_group only needs a VpcId (TargetType="instance" has no subnet
    requirement), so no subnets are provisioned.
    """
    ec2 = ctx.client("ec2")
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if default_vpcs:
        return default_vpcs[0]["VpcId"]
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-tg-attrs-vpc-")}])
    return vpc_id


def _create_tg(ctx, vpc_id, name=None, **kwargs):
    elbv2 = ctx.client("elbv2")
    name = name or ctx.unique_name("sim2real-tg-")
    params = dict(Name=name, Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="instance")
    params.update(kwargs)
    resp = elbv2.create_target_group(**params)
    tg = resp["TargetGroups"][0]
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=tg["TargetGroupArn"]))
    return tg


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
