"""modify-load-balancer-attributes-idle-timeout-round-trip."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "modify-load-balancer-attributes-idle-timeout-round-trip"
GROUP = "control-plane"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyLoadBalancerAttributes updates idle_timeout.timeout_seconds (ALB-only attribute) and
    DescribeLoadBalancerAttributes reflects the default (60s) then the new value."""
    net = _default_vpc_and_subnets(ctx)
    elbv2 = ctx.client("elbv2")
    lb = _create_alb(ctx, net["subnet_ids"])
    arn = lb["LoadBalancerArn"]

    initial = {a["Key"]: a["Value"] for a in elbv2.describe_load_balancer_attributes(LoadBalancerArn=arn)["Attributes"]}
    assert initial.get("idle_timeout.timeout_seconds") == "60", (
        f"expected a fresh ALB's idle_timeout.timeout_seconds to default to '60', "
        f"got {initial.get('idle_timeout.timeout_seconds')!r}"
    )

    elbv2.modify_load_balancer_attributes(
        LoadBalancerArn=arn, Attributes=[{"Key": "idle_timeout.timeout_seconds", "Value": "120"}]
    )

    updated = {a["Key"]: a["Value"] for a in elbv2.describe_load_balancer_attributes(LoadBalancerArn=arn)["Attributes"]}
    assert updated["idle_timeout.timeout_seconds"] == "120", (
        f"expected idle_timeout.timeout_seconds to read back '120' after the modify, "
        f"got {updated.get('idle_timeout.timeout_seconds')!r}"
    )


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
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


def _create_alb(ctx, subnet_ids, name=None):
    elbv2 = ctx.client("elbv2")
    name = name or ctx.unique_name("sim2real-elbv2-lb-")
    resp = elbv2.create_load_balancer(
        Name=name, Subnets=subnet_ids, Type="application",
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )
    lb = resp["LoadBalancers"][0]
    arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _safe(lambda: elbv2.delete_load_balancer(LoadBalancerArn=arn)))
    return lb


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
