"""list-hosted-zones-by-vpc-reflects-associations."""
from __future__ import annotations

import time
import uuid
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "list-hosted-zones-by-vpc-reflects-associations"
GROUP = "data-plane"
SERVICES = ["route53"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListHostedZonesByVPC returns exactly the set of private zones currently
    associated with the given VPC, and reflects associate/disassociate changes."""
    route53 = ctx.client("route53")

    vpc1 = _create_vpc(ctx)
    vpc2 = _create_vpc(ctx)
    vpc3 = _create_vpc(ctx)

    zone_a = route53.create_hosted_zone(
        Name=f"{ctx.unique_name('sim2real-behav-')}.zonea.com",
        CallerReference=str(uuid.uuid4()),
        VPC={"VPCRegion": ctx.region, "VPCId": vpc1},
    )["HostedZone"]["Id"]
    ctx.on_cleanup(lambda: route53.delete_hosted_zone(Id=zone_a))

    zone_b = route53.create_hosted_zone(
        Name=f"{ctx.unique_name('sim2real-behav-')}.zoneb.com",
        CallerReference=str(uuid.uuid4()),
        VPC={"VPCRegion": ctx.region, "VPCId": vpc2},
    )["HostedZone"]["Id"]
    ctx.on_cleanup(lambda: route53.delete_hosted_zone(Id=zone_b))

    # Extra association: zone A is also bound to vpc3.
    route53.associate_vpc_with_hosted_zone(
        HostedZoneId=zone_a, VPC={"VPCRegion": ctx.region, "VPCId": vpc3}
    )

    def zones_for(vpc_id: str) -> set[str]:
        summaries = route53.list_hosted_zones_by_vpc(VPCId=vpc_id, VPCRegion=ctx.region)[
            "HostedZoneSummaries"
        ]
        return {_zone_id(s["HostedZoneId"]) for s in summaries}

    # Poll the initial memberships to ride out any list eventual-consistency lag.
    r1 = _poll_until(lambda: zones_for(vpc1), lambda s: s == {_zone_id(zone_a)}, timeout_s=30.0, interval_s=2.0)
    r2 = _poll_until(lambda: zones_for(vpc2), lambda s: s == {_zone_id(zone_b)}, timeout_s=30.0, interval_s=2.0)
    r3 = _poll_until(lambda: zones_for(vpc3), lambda s: s == {_zone_id(zone_a)}, timeout_s=30.0, interval_s=2.0)
    assert r1 == {_zone_id(zone_a)}, f"vpc1 should see only zone A, got {r1}"
    assert r2 == {_zone_id(zone_b)}, f"vpc2 should see only zone B, got {r2}"
    assert r3 == {_zone_id(zone_a)}, f"vpc3 should see only zone A, got {r3}"

    # Now disassociate zone A from vpc3 (vpc1 remains, so this is allowed) and
    # confirm ListHostedZonesByVPC(vpc3) eventually stops reporting zone A.
    route53.disassociate_vpc_from_hosted_zone(
        HostedZoneId=zone_a, VPC={"VPCRegion": ctx.region, "VPCId": vpc3}
    )

    def probe() -> set[str]:
        return zones_for(vpc3)

    result = _poll_until(probe, lambda s: s == set(), timeout_s=60.0, interval_s=3.0)
    assert result == set(), f"expected vpc3 to have no zones after disassociation, got {result}"
    # vpc1's association with zone A must be unaffected by the vpc3 change.
    final_vpc1 = zones_for(vpc1)
    assert final_vpc1 == {_zone_id(zone_a)}, (
        f"vpc1's association with zone A should be unaffected by the vpc3 disassociation, "
        f"got {final_vpc1}"
    )


def _zone_id(full_id: str) -> str:
    return full_id.rsplit("/", 1)[-1]


def _create_vpc(ctx) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.0.0.0/16",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    return vpc_id


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float,
) -> Any:
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"condition not met within {timeout_s}s; last observed: {value!r}"
            )
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
