"""list-hosted-zones-by-vpc-returns-associated-zones-only."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "list-hosted-zones-by-vpc-returns-associated-zones-only"
GROUP = "visibility-timeout-ttl"
SERVICES = ["route53"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListHostedZonesByVPC lists a private zone for a VPC only while it is associated, and the
    zone stays visible via its other VPC throughout."""
    route53 = ctx.client("route53")
    ec2 = ctx.client("ec2")

    vpc_a = _create_vpc(ctx, ec2, "10.212.0.0/16", "sim2real-vpcvis-a-")

    zone_name = f"{ctx.unique_name('sim2real-vpcvis-')}.test"
    created = route53.create_hosted_zone(
        Name=zone_name,
        CallerReference=str(uuid.uuid4()),
        HostedZoneConfig={"PrivateZone": True},
        VPC={"VPCId": vpc_a, "VPCRegion": ctx.region},
    )
    zone_id = created["HostedZone"]["Id"]
    ctx.on_cleanup(lambda: route53.delete_hosted_zone(Id=zone_id))
    _wait_for_change_insync(route53, created["ChangeInfo"]["Id"])

    vpc_b = _create_vpc(ctx, ec2, "10.211.0.0/16", "sim2real-vpcvis-b-")

    # Not associated yet: must not be visible via VPC B.
    assert not _is_present(route53, vpc_b, ctx.region, zone_id), (
        f"zone {zone_id} already visible via VPC B {vpc_b} before any association was made"
    )

    assoc = route53.associate_vpc_with_hosted_zone(HostedZoneId=zone_id, VPC={"VPCId": vpc_b, "VPCRegion": ctx.region})
    _wait_for_change_insync(route53, assoc["ChangeInfo"]["Id"])

    assert _wait_until(lambda: _is_present(route53, vpc_b, ctx.region, zone_id), timeout_s=90.0, interval_s=5.0), (
        "zone did not appear in ListHostedZonesByVPC for VPC B after association committed"
    )

    disassoc = route53.disassociate_vpc_from_hosted_zone(
        HostedZoneId=zone_id, VPC={"VPCId": vpc_b, "VPCRegion": ctx.region}
    )
    _wait_for_change_insync(route53, disassoc["ChangeInfo"]["Id"])

    assert _wait_until(lambda: not _is_present(route53, vpc_b, ctx.region, zone_id), timeout_s=60.0), (
        "zone still appeared in ListHostedZonesByVPC for VPC B after disassociation"
    )

    # The zone must still be reachable via VPC A the whole time (it was never touched).
    assert _wait_until(lambda: _is_present(route53, vpc_a, ctx.region, zone_id), timeout_s=30.0), (
        f"zone {zone_id} should remain visible via VPC A {vpc_a} throughout VPC B's "
        "association/disassociation cycle, but it disappeared"
    )


def _create_vpc(ctx, ec2, cidr_block, prefix):
    vpc_id = ec2.create_vpc(
        CidrBlock=cidr_block,
        TagSpecifications=[
            {
                "ResourceType": "vpc",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name(prefix)}],
            }
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    return vpc_id


def _wait_for_change_insync(route53, change_id, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = route53.get_change(Id=change_id)["ChangeInfo"]["Status"]
        if status == "INSYNC":
            return
        time.sleep(interval_s)
    raise AssertionError(f"change {change_id} never reached INSYNC within {timeout_s}s")


def _is_present(route53, vpc_id, vpc_region, zone_id):
    bare_id = zone_id.rsplit("/", 1)[-1]
    resp = route53.list_hosted_zones_by_vpc(VPCId=vpc_id, VPCRegion=vpc_region)
    return any(s["HostedZoneId"].rsplit("/", 1)[-1] == bare_id for s in resp.get("HostedZoneSummaries", []))


def _wait_until(predicate, timeout_s, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval_s)
    return predicate()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
