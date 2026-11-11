"""modify-target-group-health-check-settings-reflected."""
from __future__ import annotations

import time
from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "modify-target-group-health-check-settings-reflected"
GROUP = "control-plane"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyTargetGroup updates health-check settings and DescribeTargetGroups reflects the new values."""
    net = _default_vpc_and_subnets(ctx)
    elbv2 = ctx.client("elbv2")
    tg = _create_target_group(
        ctx,
        net["vpc_id"],
        HealthCheckProtocol="HTTP",
        HealthCheckPath="/healthz",
        HealthCheckIntervalSeconds=30,
        HealthyThresholdCount=5,
        UnhealthyThresholdCount=5,
    )
    arn = tg["TargetGroupArn"]
    assert tg["HealthCheckPath"] == "/healthz", f"expected /healthz, got {tg['HealthCheckPath']!r}"
    assert tg["HealthCheckIntervalSeconds"] == 30, (
        f"expected 30, got {tg['HealthCheckIntervalSeconds']!r}"
    )

    elbv2.modify_target_group(
        TargetGroupArn=arn,
        HealthCheckPath="/status",
        HealthCheckIntervalSeconds=15,
        HealthyThresholdCount=3,
        UnhealthyThresholdCount=3,
        Matcher={"HttpCode": "200-299"},
    )

    described = elbv2.describe_target_groups(TargetGroupArns=[arn])["TargetGroups"][0]
    assert described["HealthCheckPath"] == "/status", (
        f"expected /status, got {described['HealthCheckPath']!r}"
    )
    assert described["HealthCheckIntervalSeconds"] == 15, (
        f"expected 15, got {described['HealthCheckIntervalSeconds']!r}"
    )
    assert described["HealthyThresholdCount"] == 3, (
        f"expected 3, got {described['HealthyThresholdCount']!r}"
    )
    assert described["UnhealthyThresholdCount"] == 3, (
        f"expected 3, got {described['UnhealthyThresholdCount']!r}"
    )
    assert described["Matcher"]["HttpCode"] == "200-299", (
        f"expected 200-299, got {described['Matcher']['HttpCode']!r}"
    )


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TargetGroupNotFound":
            raise


def _default_vpc_and_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s)
    if len(by_az) < 2:
        raise AssertionError("shared network does not have subnets in at least 2 availability zones")
    chosen = list(by_az.values())[:2]
    return {
        "vpc_id": vpc_id,
        "subnet_ids": [s["SubnetId"] for s in chosen],
        "subnet_cidrs": [s["CidrBlock"] for s in chosen],
    }


def _create_target_group(ctx, vpc_id, **kwargs):
    elbv2 = ctx.client("elbv2")
    name = kwargs.pop("Name", None) or ctx.unique_name("sim2real-elbv2-tg-")
    params = {
        "Name": name,
        "Protocol": "HTTP",
        "Port": 80,
        "VpcId": vpc_id,
        "TargetType": "ip",
        "Tags": [{"Key": "sim2real", "Value": "true"}],
    }
    params.update(kwargs)
    resp = elbv2.create_target_group(**params)
    tg = resp["TargetGroups"][0]
    arn = tg["TargetGroupArn"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_target_group_when_free(elbv2, arn)))
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
