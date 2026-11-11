"""op-contract-describe-target-groups."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-target-groups"
GROUP = "error-semantics"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTargetGroups filters by Name/ARN correctly; an unknown TG name is rejected as not-found."""
    vpc_id, _ = _default_vpc_and_subnets(ctx)
    elbv2 = ctx.client("elbv2")
    tg1 = _create_tg(ctx, vpc_id, name=ctx.unique_name("sim2real-tg-a-"))
    tg2 = _create_tg(ctx, vpc_id, name=ctx.unique_name("sim2real-tg-b-"), Port=8080)

    by_name = elbv2.describe_target_groups(Names=[tg1["TargetGroupName"]])["TargetGroups"]
    assert len(by_name) == 1, f"expected exactly 1 TG named {tg1['TargetGroupName']!r}, got {by_name}"
    assert by_name[0]["TargetGroupArn"] == tg1["TargetGroupArn"], (
        f"expected ARN {tg1['TargetGroupArn']}, got {by_name[0]['TargetGroupArn']}"
    )
    assert by_name[0]["Port"] == 80, f"expected port 80, got {by_name[0]['Port']}"

    by_arn = elbv2.describe_target_groups(TargetGroupArns=[tg2["TargetGroupArn"]])["TargetGroups"]
    assert len(by_arn) == 1, f"expected exactly 1 TG for ARN {tg2['TargetGroupArn']}, got {by_arn}"
    assert by_arn[0]["TargetGroupArn"] == tg2["TargetGroupArn"], (
        f"expected ARN {tg2['TargetGroupArn']}, got {by_arn[0]['TargetGroupArn']}"
    )
    assert by_arn[0]["Port"] == 8080, f"expected port 8080, got {by_arn[0]['Port']}"

    both = elbv2.describe_target_groups(
        TargetGroupArns=[tg1["TargetGroupArn"], tg2["TargetGroupArn"]]
    )["TargetGroups"]
    got_arns = {t["TargetGroupArn"] for t in both}
    expected_arns = {tg1["TargetGroupArn"], tg2["TargetGroupArn"]}
    assert got_arns == expected_arns, f"expected both ARNs {expected_arns}, got {got_arns}"

    missing_name = ctx.unique_name("sim2real-tg-missing-")
    code, message = _error(lambda: elbv2.describe_target_groups(Names=[missing_name]))
    # Real AWS's ELBv2 API returns the error type WITHOUT the "Exception" suffix on the wire
    # (unlike the shape name used by the botocore model / docs).
    assert code == "TargetGroupNotFound", f"expected not-found, got {code}"
    expected = "One or more target groups not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to fail, but it SUCCEEDED and returned {result!r}")


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


def _tags_kv(ctx):
    return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}]


def _create_tg(ctx, vpc_id, name=None, **kwargs):
    elbv2 = ctx.client("elbv2")
    name = name or ctx.unique_name("sim2real-tg-")
    params = dict(
        Name=name, Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="instance",
        Tags=_tags_kv(ctx),
    )
    params.update(kwargs)
    resp = elbv2.create_target_group(**params)
    tg = resp["TargetGroups"][0]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg["TargetGroupArn"]))
    return tg



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
