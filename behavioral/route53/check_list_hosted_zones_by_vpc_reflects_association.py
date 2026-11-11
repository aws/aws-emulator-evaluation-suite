"""list-hosted-zones-by-vpc-reflects-association."""
from __future__ import annotations

import itertools
import random
import time
from typing import Any

from behavioral_harness import tags

CHECK = "list-hosted-zones-by-vpc-reflects-association"
GROUP = "server-side"
SERVICES = ["route53"]

_octet_counter = itertools.count(random.randint(20, 200))


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListHostedZonesByVPC excludes a zone before association, includes it immediately after
    AssociateVPCWithHostedZone reaches INSYNC, and excludes it again immediately after
    DisassociateVPCFromHostedZone reaches INSYNC."""
    route53 = ctx.client("route53")
    vpc_a = _create_vpc(ctx)  # zone's permanent VPC (keeps the zone non-empty of VPCs)
    vpc_b = _create_vpc(ctx)  # the VPC whose membership we associate/disassociate
    zone_id = _create_private_zone(ctx, vpc_a)

    # Before association: vpc_b sees no such zone.
    before = _poll_until(
        lambda: _zone_ids_for_vpc(ctx, vpc_b),
        lambda ids: zone_id not in ids,
        timeout_s=20,
    )
    assert zone_id not in before, f"zone unexpectedly visible to vpc_b before association: {before}"

    # Associate vpc_b with the zone.
    resp = route53.associate_vpc_with_hosted_zone(
        HostedZoneId=zone_id, VPC={"VPCRegion": ctx.region, "VPCId": vpc_b}
    )
    _wait_change_insync(ctx, resp["ChangeInfo"]["Id"])

    after_associate = _poll_until(
        lambda: _zone_ids_for_vpc(ctx, vpc_b),
        lambda ids: zone_id in ids,
        timeout_s=30,
    )
    assert zone_id in after_associate, f"zone not visible to vpc_b after association: {after_associate}"

    # Disassociate vpc_b (vpc_a remains, so this isn't the LastVPCAssociation).
    resp = route53.disassociate_vpc_from_hosted_zone(
        HostedZoneId=zone_id, VPC={"VPCRegion": ctx.region, "VPCId": vpc_b}
    )
    _wait_change_insync(ctx, resp["ChangeInfo"]["Id"])

    after_disassociate = _poll_until(
        lambda: _zone_ids_for_vpc(ctx, vpc_b),
        lambda ids: zone_id not in ids,
        timeout_s=30,
    )
    assert zone_id not in after_disassociate, (
        f"zone still visible to vpc_b after disassociation: {after_disassociate}"
    )

    # vpc_a's own association must be unaffected by disassociating vpc_b.
    still_on_vpc_a = _zone_ids_for_vpc(ctx, vpc_a)
    assert zone_id in still_on_vpc_a, (
        f"zone lost its association with vpc_a after disassociating an unrelated vpc_b: {still_on_vpc_a}"
    )


def _zone_ids_for_vpc(ctx: Any, vpc_id: str) -> set[str]:
    route53 = ctx.client("route53")
    resp = route53.list_hosted_zones_by_vpc(VPCId=vpc_id, VPCRegion=ctx.region)
    return {s["HostedZoneId"] for s in resp.get("HostedZoneSummaries", [])}


def _poll_until(probe, predicate, timeout_s: float = 30.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed: {last!r}")


def _create_vpc(ctx: Any) -> str:
    ec2 = ctx.client("ec2")
    octet = next(_octet_counter) % 250
    cidr = f"10.{octet}.0.0/16"
    name = ctx.unique_name("sim2real-r53-vpc-")
    resp = ec2.create_vpc(
        CidrBlock=cidr,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    vpc_id = resp["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda v=vpc_id: ec2.delete_vpc(VpcId=v))
    _wait_vpc_available(ctx, vpc_id)
    return vpc_id


def _wait_vpc_available(ctx: Any, vpc_id: str, timeout_s: float = 30.0, interval_s: float = 2.0) -> None:
    ec2 = ctx.client("ec2")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"]
        if state == "available":
            return
        time.sleep(interval_s)
    raise AssertionError(f"vpc {vpc_id} never became available within {timeout_s}s (last state {state})")


def _create_private_zone(ctx: Any, vpc_id: str, name: str | None = None) -> str:
    route53 = ctx.client("route53")
    if name is None:
        name = f"{ctx.unique_name('sim2real-r53-')}.example.com."
    resp = route53.create_hosted_zone(
        Name=name,
        CallerReference=ctx.unique_name("sim2real-callerref-"),
        HostedZoneConfig={"PrivateZone": True},
        VPC={"VPCRegion": ctx.region, "VPCId": vpc_id},
    )
    zone_id = resp["HostedZone"]["Id"].split("/")[-1]
    ctx.on_cleanup(lambda z=zone_id: route53.delete_hosted_zone(Id=z))
    _wait_change_insync(ctx, resp["ChangeInfo"]["Id"])
    return zone_id


def _wait_change_insync(ctx: Any, change_id: str, timeout_s: float = 180.0, interval_s: float = 3.0) -> None:
    route53 = ctx.client("route53")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = route53.get_change(Id=change_id)["ChangeInfo"]["Status"]
        if status == "INSYNC":
            return
        time.sleep(interval_s)
    raise AssertionError(f"change {change_id} never reached INSYNC within {timeout_s}s (last {status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
