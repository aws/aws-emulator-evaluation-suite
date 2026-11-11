"""disassociate-last-vpc-from-private-zone-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disassociate-last-vpc-from-private-zone-rejected"
GROUP = "overly-permissive"
SERVICES = ["route53"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisassociateVPCFromHostedZone rejects removing the *only* remaining VPC
    association of a private hosted zone with LastVPCAssociation -- a private
    zone can never be left with zero VPC associations via this call."""
    route53 = ctx.client("route53")

    vpc1 = _create_vpc(ctx)
    vpc2 = _create_vpc(ctx)

    zone_id = route53.create_hosted_zone(
        Name=f"{ctx.unique_name('sim2real-behav-')}.example.com",
        CallerReference=str(uuid.uuid4()),
        VPC={"VPCRegion": ctx.region, "VPCId": vpc1},
    )["HostedZone"]["Id"]
    ctx.on_cleanup(lambda: route53.delete_hosted_zone(Id=zone_id))

    # Add a second VPC so we can demonstrate that disassociation normally works
    # (positive control) before narrowing down to the single-VPC boundary case.
    route53.associate_vpc_with_hosted_zone(
        HostedZoneId=zone_id, VPC={"VPCRegion": ctx.region, "VPCId": vpc2}
    )

    # Positive control: removing vpc2 while vpc1 remains succeeds.
    route53.disassociate_vpc_from_hosted_zone(
        HostedZoneId=zone_id, VPC={"VPCRegion": ctx.region, "VPCId": vpc2}
    )
    remaining = route53.list_hosted_zones_by_vpc(VPCId=vpc1, VPCRegion=ctx.region)[
        "HostedZoneSummaries"
    ]
    assert any(_zone_id(s["HostedZoneId"]) == _zone_id(zone_id) for s in remaining), (
        f"expected {zone_id!r} to still be listed for vpc1 {vpc1!r} after the vpc2 "
        f"disassociation, got {remaining!r}"
    )

    # Now break exactly one thing: try to remove the last remaining VPC (vpc1).
    code, message = _error(
        lambda: route53.disassociate_vpc_from_hosted_zone(
            HostedZoneId=zone_id, VPC={"VPCRegion": ctx.region, "VPCId": vpc1}
        )
    )
    assert code == "LastVPCAssociation", f"expected LastVPCAssociation, got {code!r}"
    expected = "Cannot remove last VPC association for private zone"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: vpc1 must still be associated with the zone.
    still_there = route53.list_hosted_zones_by_vpc(VPCId=vpc1, VPCRegion=ctx.region)[
        "HostedZoneSummaries"
    ]
    assert any(_zone_id(s["HostedZoneId"]) == _zone_id(zone_id) for s in still_there), (
        "the rejected disassociation must not have removed vpc1's association"
    )

    # Restore: the rejection is state-dependent (only-remaining-VPC), not an
    # always-invalid input, so it must become the identical *successful* call once
    # a second VPC is associated again.
    vpc3 = _create_vpc(ctx)
    route53.associate_vpc_with_hosted_zone(
        HostedZoneId=zone_id, VPC={"VPCRegion": ctx.region, "VPCId": vpc3}
    )
    route53.disassociate_vpc_from_hosted_zone(
        HostedZoneId=zone_id, VPC={"VPCRegion": ctx.region, "VPCId": vpc1}
    )
    after_restore = route53.list_hosted_zones_by_vpc(VPCId=vpc3, VPCRegion=ctx.region)[
        "HostedZoneSummaries"
    ]
    assert any(_zone_id(s["HostedZoneId"]) == _zone_id(zone_id) for s in after_restore), (
        f"expected {zone_id!r} reachable via vpc3 {vpc3!r} after the identical "
        f"disassociate(vpc1) call succeeded once vpc1 was no longer the last VPC, "
        f"got {after_restore!r}"
    )
    vpc1_listing = route53.list_hosted_zones_by_vpc(VPCId=vpc1, VPCRegion=ctx.region)[
        "HostedZoneSummaries"
    ]
    assert not any(_zone_id(s["HostedZoneId"]) == _zone_id(zone_id) for s in vpc1_listing), (
        f"expected vpc1 {vpc1!r} disassociation to have taken effect, got {vpc1_listing!r}"
    )


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected success raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
