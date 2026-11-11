"""load-balancer-and-target-group-tags-visible-through-get-resources."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "load-balancer-and-target-group-tags-visible-through-get-resources"
GROUP = "tagging-discovery"
SERVICES = ["elbv2", "resourcegroupstaggingapi"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """elbv2 AddTags on an ALB and a target group makes both discoverable by one GetResources tag
    filter, and elbv2 RemoveTags withdraws both from the tagging index.
    """
    elbv2 = ctx.client("elbv2")
    rgt = ctx.client("resourcegroupstaggingapi")

    key = ctx.unique_name("sim2real-behav-k-")
    value = ctx.unique_name("sim2real-behav-v-")

    net = _own_vpc_and_two_subnets(ctx)
    tg_arn = _create_target_group(ctx, net["vpc_id"])
    lb_arn = _create_load_balancer(ctx, net["subnet_ids"])

    # elbv2's AddTags accepts only one resource per call, so the two resource types are
    # tagged separately even though they share the same key/value.
    elbv2.add_tags(ResourceArns=[lb_arn], Tags=[{"Key": key, "Value": value}])
    elbv2.add_tags(ResourceArns=[tg_arn], Tags=[{"Key": key, "Value": value}])

    found = _poll_until(
        lambda: rgt.get_resources(
            TagFilters=[{"Key": key, "Values": [value]}]
        )["ResourceTagMappingList"],
        lambda mappings: {m["ResourceARN"] for m in mappings} == {lb_arn, tg_arn},
        timeout_s=120.0,
    )
    arns = {m["ResourceARN"] for m in found}
    assert arns == {lb_arn, tg_arn}, (
        f"tag filter {key}={value!r} returned {sorted(arns)!r}, expected exactly the load "
        f"balancer {lb_arn!r} and the target group {tg_arn!r}"
    )

    elbv2.remove_tags(ResourceArns=[lb_arn], TagKeys=[key])
    elbv2.remove_tags(ResourceArns=[tg_arn], TagKeys=[key])

    gone = _poll_until(
        lambda: rgt.get_resources(
            TagFilters=[{"Key": key, "Values": [value]}]
        )["ResourceTagMappingList"],
        lambda mappings: mappings == [],
        timeout_s=120.0,
    )
    assert gone == [], (
        f"RemoveTags cleared {key}={value!r} from elbv2's own DescribeTags, but the tagging "
        f"index still reports {gone!r}"
    )


def _own_vpc_and_two_subnets(ctx):
    """A new VPC with one subnet in each of two AZs, enough for an internal ALB (no IGW needed).

    Deletes are registered first so they run last.
    """
    ec2 = ctx.client("ec2")
    tag = [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-lbvpc-")}]
    vpc_id = ec2.create_vpc(
        CidrBlock="10.72.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": tag}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    zones = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "zone-type", "Values": ["availability-zone"]},
                     {"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    )
    assert len(zones) >= 2, f"an ALB needs two AZs; {ctx.region} offers {zones!r}"
    subnet_ids = []
    for i, zone in enumerate(zones[:2]):
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.72.{i}.0/24", AvailabilityZone=zone,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": tag}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(
            lambda sid=sid: _retry_dependency(lambda: ec2.delete_subnet(SubnetId=sid))
        )
        subnet_ids.append(sid)
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids}


def _retry_dependency(fn, timeout_s=240.0, interval_s=10.0):
    """Retry fn on DependencyViolation until the deadline; anything else raises.

    A deleted ALB releases its ENIs asynchronously, so subnet/VPC deletes fail for a while.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "DependencyViolation" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _create_target_group(ctx, vpc_id):
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-behav-tg-")
    arn = elbv2.create_target_group(
        Name=name, Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="ip",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=arn))
    return arn


def _create_load_balancer(ctx, subnet_ids):
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-behav-lb-")
    arn = elbv2.create_load_balancer(
        Name=name, Subnets=subnet_ids, Scheme="internal", Type="application",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=arn))
    return arn


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while time.monotonic() < deadline:
        if predicate(last):
            return last
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
