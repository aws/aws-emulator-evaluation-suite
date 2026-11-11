"""disassociate-last-vpc-association-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disassociate-last-vpc-association-rejected"
GROUP = "ordering"
SERVICES = ["route53"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisassociateVPCFromHostedZone on the *only* remaining VPC is rejected with
    LastVPCAssociation, leaves the association intact, and the same operation succeeds
    once a second VPC is associated (positive control in-file)."""
    route53 = ctx.client("route53")
    vpc1 = _create_vpc(ctx)
    zone_id = _create_private_hosted_zone(ctx, vpc1)

    # --- negative: only one VPC is associated, disassociating it must be rejected ---
    code, message = _error_code(
        lambda: route53.disassociate_vpc_from_hosted_zone(
            HostedZoneId=zone_id, VPC={"VPCRegion": ctx.region, "VPCId": vpc1}
        )
    )
    assert code == "LastVPCAssociation", f"expected LastVPCAssociation, got {code!r}"
    assert message == "Cannot remove last VPC association for private zone", (
        f"expected message 'Cannot remove last VPC association for private zone', got {message!r}"
    )

    # effect absent: the zone is still associated with vpc1
    still_associated = _poll_zone_ids_by_vpc(ctx, vpc1, lambda ids: zone_id in ids)
    assert zone_id in still_associated, (
        f"rejected disassociation must not remove vpc1's association, saw {still_associated!r}"
    )

    # --- positive control: with a second VPC associated, disassociating vpc1 succeeds ---
    vpc2 = _create_vpc(ctx)
    route53.create_vpc_association_authorization(
        HostedZoneId=zone_id, VPC={"VPCRegion": ctx.region, "VPCId": vpc2}
    )
    ctx.on_cleanup(
        lambda: _safe(
            lambda: route53.delete_vpc_association_authorization(
                HostedZoneId=zone_id, VPC={"VPCRegion": ctx.region, "VPCId": vpc2}
            ),
            "VPCAssociationAuthorizationNotFound",
            "NoSuchHostedZone",
        )
    )
    route53.associate_vpc_with_hosted_zone(
        HostedZoneId=zone_id, VPC={"VPCRegion": ctx.region, "VPCId": vpc2}
    )
    _poll_zone_ids_by_vpc(ctx, vpc2, lambda ids: zone_id in ids)

    route53.disassociate_vpc_from_hosted_zone(
        HostedZoneId=zone_id, VPC={"VPCRegion": ctx.region, "VPCId": vpc1}
    )
    removed = _poll_zone_ids_by_vpc(ctx, vpc1, lambda ids: zone_id not in ids)
    assert zone_id not in removed, (
        f"disassociating vpc1 must succeed once a second VPC is associated, saw {removed!r}"
    )
    # zone is now only associated with vpc2 -- confirm it's still reachable there
    still_via_vpc2 = _list_zone_ids_by_vpc(ctx, vpc2)
    assert zone_id in still_via_vpc2, (
        f"zone must still be reachable via vpc2 after vpc1 disassociation, saw {still_via_vpc2!r}"
    )


def _safe(fn, *gone: str) -> None:
    """Teardown call: return on the listed not-found codes, raise every other failure."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in gone:
            raise


def _error_code(fn) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_vpc(ctx) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-r53-vpc-")
    resp = ec2.create_vpc(
        CidrBlock="10.88.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    vpc_id = resp["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_vpc(VpcId=vpc_id), "InvalidVpcID.NotFound"))
    return vpc_id


def _create_private_hosted_zone(ctx, vpc_id: str) -> str:
    route53 = ctx.client("route53")
    name = ctx.unique_name("sim2real-r53-lastvpc-") + ".internal."
    resp = route53.create_hosted_zone(
        Name=name,
        CallerReference=ctx.unique_name("sim2real-r53-cr-"),
        HostedZoneConfig={"PrivateZone": True},
        VPC={"VPCRegion": ctx.region, "VPCId": vpc_id},
    )
    zone_id = resp["HostedZone"]["Id"].split("/")[-1]
    ctx.on_cleanup(lambda: _safe(lambda: route53.delete_hosted_zone(Id=zone_id), "NoSuchHostedZone"))
    return zone_id


def _list_zone_ids_by_vpc(ctx, vpc_id: str) -> set[str]:
    route53 = ctx.client("route53")
    resp = route53.list_hosted_zones_by_vpc(VPCId=vpc_id, VPCRegion=ctx.region)
    return {s["HostedZoneId"] for s in resp.get("HostedZoneSummaries", [])}


def _poll_zone_ids_by_vpc(
    ctx, vpc_id: str, predicate, timeout_s: float = 90.0, interval_s: float = 3.0
) -> set[str]:
    deadline = time.monotonic() + timeout_s
    last: set[str] = set()
    while time.monotonic() < deadline:
        last = _list_zone_ids_by_vpc(ctx, vpc_id)
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"ListHostedZonesByVPC never satisfied predicate, last saw {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
