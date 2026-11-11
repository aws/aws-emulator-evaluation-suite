"""e2e-cross-account-vpc-authorization-then-association-consequence."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-cross-account-vpc-authorization-then-association-consequence"
GROUP = "e2e"
SERVICES = ["route53"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Revoking a VPC association authorization removes it but keeps the existing association.

    The associated VPC stays visible via ListHostedZonesByVPC, and a second revoke is rejected.
    """
    route53 = ctx.client("route53")

    vpc_a = _create_vpc(ctx)
    zone_id, _zone_name = _create_private_zone(ctx, vpc_a)
    vpc_b = _create_vpc(ctx)

    # --- authorize VPC-B for association with the private zone ---
    route53.create_vpc_association_authorization(
        HostedZoneId=zone_id, VPC={"VPCId": vpc_b, "VPCRegion": ctx.region}
    )
    auths = route53.list_vpc_association_authorizations(HostedZoneId=zone_id)["VPCs"]
    assert any(v["VPCId"] == vpc_b for v in auths), "authorization for VPC-B not listed"

    # --- consume the authorization: associate VPC-B with the zone ---
    assoc_resp = route53.associate_vpc_with_hosted_zone(
        HostedZoneId=zone_id, VPC={"VPCId": vpc_b, "VPCRegion": ctx.region}
    )
    _wait_change_insync(ctx, assoc_resp["ChangeInfo"]["Id"])

    summaries = _list_zones_by_vpc(ctx, vpc_b)
    assert zone_id.split("/")[-1] in summaries, "zone not visible via ListHostedZonesByVPC(VPC-B)"

    # --- revoke the authorization ---
    route53.delete_vpc_association_authorization(
        HostedZoneId=zone_id, VPC={"VPCId": vpc_b, "VPCRegion": ctx.region}
    )
    auths_after = route53.list_vpc_association_authorizations(HostedZoneId=zone_id)["VPCs"]
    assert not any(v["VPCId"] == vpc_b for v in auths_after), (
        "authorization for VPC-B still listed after revocation"
    )

    # --- the existing association must persist despite the authorization being gone ---
    summaries_after_revoke = _list_zones_by_vpc(ctx, vpc_b)
    assert zone_id.split("/")[-1] in summaries_after_revoke, (
        "existing VPC association disappeared after revoking the (already-consumed) authorization"
    )

    # --- revoking an authorization that no longer exists is rejected ---
    err = _client_error(
        lambda: route53.delete_vpc_association_authorization(
            HostedZoneId=zone_id, VPC={"VPCId": vpc_b, "VPCRegion": ctx.region}
        )
    )
    assert err["Code"] == "VPCAssociationAuthorizationNotFound", (
        f"expected VPCAssociationAuthorizationNotFound, got {err}"
    )
    assert err["Message"] == (
        "No authorization exists for hosted zone: "
        f"{zone_id.split('/')[-1]} and vpc: {vpc_b}, {ctx.region}"
    ), err

    # --- teardown of the VPC-B association (leaves VPC-A as the sole association) ---
    disassoc_resp = route53.disassociate_vpc_from_hosted_zone(
        HostedZoneId=zone_id, VPC={"VPCId": vpc_b, "VPCRegion": ctx.region}
    )
    _wait_change_insync(ctx, disassoc_resp["ChangeInfo"]["Id"])
    summaries_final = _list_zones_by_vpc(ctx, vpc_b)
    assert zone_id.split("/")[-1] not in summaries_final, (
        "zone still visible via ListHostedZonesByVPC(VPC-B) after disassociation"
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _client_error(fn):
    """The ``Error`` of the ClientError ``fn`` raises. A call that succeeds fails the check: a
    target accepting what AWS refuses must not read as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _wait_change_insync(ctx, change_id: str) -> None:
    route53 = ctx.client("route53")
    status = _poll_until(
        probe=lambda: route53.get_change(Id=change_id)["ChangeInfo"]["Status"],
        predicate=lambda s: s == "INSYNC",
        timeout_s=120,
        interval_s=5,
    )
    assert status == "INSYNC", f"change {change_id} never reached INSYNC, last={status}"


def _create_vpc(ctx) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-r53vpc-")
    resp = ec2.create_vpc(
        CidrBlock="10.211.0.0/24",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )
    vpc_id = resp["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe_delete_vpc(ctx, vpc_id))
    return vpc_id


def _create_private_zone(ctx, vpc_id: str) -> tuple[str, str]:
    route53 = ctx.client("route53")
    zone_name = f"{ctx.unique_name('sim2real-vpcauth-zone')}.com.".replace("_", "-")
    resp = route53.create_hosted_zone(
        Name=zone_name,
        CallerReference=ctx.unique_name("vpcauth-zone-ref"),
        VPC={"VPCId": vpc_id, "VPCRegion": ctx.region},
    )
    zone_id = resp["HostedZone"]["Id"]
    _wait_change_insync(ctx, resp["ChangeInfo"]["Id"])
    ctx.on_cleanup(lambda: _safe_delete_zone(ctx, zone_id))
    return zone_id, zone_name


def _list_zones_by_vpc(ctx, vpc_id: str) -> set[str]:
    route53 = ctx.client("route53")
    resp = route53.list_hosted_zones_by_vpc(VPCId=vpc_id, VPCRegion=ctx.region)
    return {s["HostedZoneId"] for s in resp.get("HostedZoneSummaries", [])}


def _safe_delete_zone(ctx, zone_id: str) -> None:
    route53 = ctx.client("route53")
    try:
        route53.delete_hosted_zone(Id=zone_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchHostedZone":
            raise


def _safe_delete_vpc(ctx, vpc_id: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        ec2.delete_vpc(VpcId=vpc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVpcID.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
