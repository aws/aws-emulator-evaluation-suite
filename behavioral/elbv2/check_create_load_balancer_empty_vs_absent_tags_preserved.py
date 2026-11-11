"""create-load-balancer-empty-vs-absent-tags-preserved."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "create-load-balancer-empty-vs-absent-tags-preserved"
GROUP = "representation"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A never-tagged load balancer reports Tags=[] via DescribeTags, and tagging then removing every
    tag converges to the identical TagDescriptions entry."""
    elbv2 = ctx.client("elbv2")
    ec2 = ctx.client("ec2")

    net = _create_network(ctx, ec2)
    # Tags is omitted: its minimum length is 1, so an explicit empty list cannot be sent.
    lb_arn = elbv2.create_load_balancer(
        Name=ctx.unique_name("sim2real-elbv2-")[:32].rstrip("-"),
        Subnets=net["subnet_ids"],
        SecurityGroups=[net["sg_id"]],
        Scheme="internal",
        Type="application",
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _delete_lb_and_wait(elbv2, lb_arn))

    never_tagged = elbv2.describe_tags(ResourceArns=[lb_arn])["TagDescriptions"][0]
    assert never_tagged["Tags"] == [], f"a freshly created, never-tagged LB must report Tags=[], got {never_tagged['Tags']!r}"

    elbv2.add_tags(ResourceArns=[lb_arn], Tags=[{"Key": "temp-key", "Value": "temp-value"}])
    tagged = elbv2.describe_tags(ResourceArns=[lb_arn])["TagDescriptions"][0]
    assert tagged["Tags"] == [{"Key": "temp-key", "Value": "temp-value"}], (
        f"expected exactly the one added tag, got {tagged['Tags']!r}"
    )

    elbv2.remove_tags(ResourceArns=[lb_arn], TagKeys=["temp-key"])
    cleared = elbv2.describe_tags(ResourceArns=[lb_arn])["TagDescriptions"][0]
    assert cleared["Tags"] == [], f"after removing the only tag, Tags must be [] again, got {cleared['Tags']!r}"
    assert cleared == never_tagged, (
        "a load balancer that was tagged and fully cleared must be indistinguishable via "
        f"DescribeTags from one that was never tagged: {cleared!r} vs {never_tagged!r}"
    )



def _create_network(ctx, ec2) -> dict[str, Any]:
    vpc_id = ec2.create_vpc(CidrBlock="10.85.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones()["AvailabilityZones"]
        if z["State"] == "available"
    ][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.85.{i}.0/24", AvailabilityZone=az)["Subnet"][
            "SubnetId"
        ]
        subnet_ids.append(sid)
        ctx.on_cleanup(lambda sid=sid: _retry_delete(lambda: ec2.delete_subnet(SubnetId=sid)))
    sg_id = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=ctx.unique_name("sim2real-elbv2-sg-"),
        Description="sim2real elbv2 tag representation behavioral check",
    )["GroupId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_security_group(GroupId=sg_id)))
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "sg_id": sg_id}


def _retry_delete(fn, attempts: int = 24, delay: float = 5.0) -> None:
    last: Exception | None = None
    for _ in range(attempts):
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            if code in ("DependencyViolation", "InvalidGroup.InUse", "InvalidVpcID.InUse"):
                last = exc
                time.sleep(delay)
                continue
            raise
    if last:
        raise last


def _delete_lb_and_wait(elbv2, lb_arn: str, timeout_s: float = 180) -> None:
    try:
        elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)
    except elbv2.exceptions.LoadBalancerNotFoundException:
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])
        except elbv2.exceptions.LoadBalancerNotFoundException:
            return
        time.sleep(5)
    raise AssertionError("load balancer was not removed within timeout")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
