"""e2e-cross-account-vpc-association-flow."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-cross-account-vpc-association-flow"
GROUP = "ordering"
SERVICES = ["route53"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Authorize -> associate -> ListHostedZonesByVPC reflects it -> disassociate -> revoke
    -> ListHostedZonesByVPC no longer reflects it (the full VPC-association-authorization
    ordering contract, exercised end to end)."""
    route53 = ctx.client("route53")
    vpc1 = _create_vpc(ctx)
    vpc2 = _create_vpc(ctx)
    zone_id = _create_private_hosted_zone(ctx, vpc1)

    # Not yet associated: the zone must not show up under vpc2.
    before = _list_zone_ids_by_vpc(ctx, vpc2)
    assert zone_id not in before, (
        f"zone {zone_id} already listed under unassociated vpc {vpc2}: {before}"
    )

    route53.create_vpc_association_authorization(
        HostedZoneId=zone_id, VPC={"VPCRegion": ctx.region, "VPCId": vpc2}
    )
    authorized = True

    def _revoke_if_needed() -> None:
        nonlocal authorized
        if authorized:
            try:
                route53.delete_vpc_association_authorization(
                    HostedZoneId=zone_id, VPC={"VPCRegion": ctx.region, "VPCId": vpc2}
                )
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in (
                    "HostedZoneNotFound",
                    "NoSuchHostedZone",
                    "VPCAssociationAuthorizationNotFound",
                ):
                    raise

    ctx.on_cleanup(_revoke_if_needed)

    auths = route53.list_vpc_association_authorizations(HostedZoneId=zone_id)["VPCs"]
    assert any(v["VPCId"] == vpc2 for v in auths), (
        f"expected vpc {vpc2} in authorizations for zone {zone_id}, got {auths}"
    )

    route53.associate_vpc_with_hosted_zone(
        HostedZoneId=zone_id, VPC={"VPCRegion": ctx.region, "VPCId": vpc2}
    )

    def _disassociate_if_needed() -> None:
        try:
            route53.disassociate_vpc_from_hosted_zone(
                HostedZoneId=zone_id, VPC={"VPCRegion": ctx.region, "VPCId": vpc2}
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "HostedZoneNotFound",
                "NoSuchHostedZone",
                "VPCAssociationNotFound",
            ):
                raise

    ctx.on_cleanup(_disassociate_if_needed)

    associated = _poll_zone_ids_by_vpc(ctx, vpc2, lambda ids: zone_id in ids)
    assert zone_id in associated, (
        f"expected zone {zone_id} listed under vpc {vpc2} after associate, got {associated}"
    )

    route53.disassociate_vpc_from_hosted_zone(
        HostedZoneId=zone_id, VPC={"VPCRegion": ctx.region, "VPCId": vpc2}
    )
    disassociated = _poll_zone_ids_by_vpc(ctx, vpc2, lambda ids: zone_id not in ids)
    assert zone_id not in disassociated, (
        f"expected zone {zone_id} absent from vpc {vpc2} after disassociate, got {disassociated}"
    )

    route53.delete_vpc_association_authorization(
        HostedZoneId=zone_id, VPC={"VPCRegion": ctx.region, "VPCId": vpc2}
    )
    authorized = False

    remaining_auths = route53.list_vpc_association_authorizations(HostedZoneId=zone_id)["VPCs"]
    assert not any(v["VPCId"] == vpc2 for v in remaining_auths), (
        f"expected vpc {vpc2} absent from authorizations for zone {zone_id} after revoke, "
        f"got {remaining_auths}"
    )


def _safe(fn, *gone: str) -> None:
    """Teardown call: return on the listed not-found codes, raise every other failure."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in gone:
            raise


def _create_vpc(ctx) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-r53-vpc-")
    resp = ec2.create_vpc(
        CidrBlock="10.77.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    vpc_id = resp["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_vpc(VpcId=vpc_id), "InvalidVpcID.NotFound"))
    return vpc_id


def _create_private_hosted_zone(ctx, vpc_id: str) -> str:
    route53 = ctx.client("route53")
    name = ctx.unique_name("sim2real-r53-priv-") + ".internal."
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
