"""vpc-association-requires-authorization-denied."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "vpc-association-requires-authorization-denied"
GROUP = "overly-permissive"
SERVICES = ["route53"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Revoking a VPC association authorization that was never granted, or was already revoked,
    fails with VPCAssociationAuthorizationNotFound rather than succeeding as a no-op.
    """
    route53 = ctx.client("route53")

    vpc1 = _create_vpc(ctx)
    vpc2 = _create_vpc(ctx)

    zone_id = route53.create_hosted_zone(
        Name=f"{ctx.unique_name('sim2real-behav-')}.example.com",
        CallerReference=str(uuid.uuid4()),
        VPC={"VPCRegion": ctx.region, "VPCId": vpc1},
    )["HostedZone"]["Id"]
    ctx.on_cleanup(lambda: route53.delete_hosted_zone(Id=zone_id))

    not_found = (
        f"No authorization exists for hosted zone: {zone_id.split('/')[-1]} "
        f"and vpc: {vpc2}, {ctx.region}"
    )
    err = _client_error(
        lambda: route53.delete_vpc_association_authorization(
            HostedZoneId=zone_id, VPC={"VPCRegion": ctx.region, "VPCId": vpc2}
        )
    )
    assert err.get("Code") == "VPCAssociationAuthorizationNotFound", (
        f"expected VPCAssociationAuthorizationNotFound, got {err!r}"
    )
    assert err.get("Message") == not_found, err
    # Effect absent: no authorization exists for vpc2 on this zone.
    assert not _authorized_vpc_ids(route53, zone_id, ctx.region), (
        "vpc2 must not appear as authorized after a rejected revoke of a never-granted "
        "authorization"
    )

    route53.create_vpc_association_authorization(
        HostedZoneId=zone_id, VPC={"VPCRegion": ctx.region, "VPCId": vpc2}
    )
    assert vpc2 in _authorized_vpc_ids(route53, zone_id, ctx.region), (
        "vpc2 should appear as an authorized VPC after granting"
    )
    route53.delete_vpc_association_authorization(
        HostedZoneId=zone_id, VPC={"VPCRegion": ctx.region, "VPCId": vpc2}
    )
    assert vpc2 not in _authorized_vpc_ids(route53, zone_id, ctx.region), (
        "vpc2 should no longer be authorized after revocation"
    )

    err2 = _client_error(
        lambda: route53.delete_vpc_association_authorization(
            HostedZoneId=zone_id, VPC={"VPCRegion": ctx.region, "VPCId": vpc2}
        )
    )
    assert err2.get("Code") == "VPCAssociationAuthorizationNotFound", (
        f"expected VPCAssociationAuthorizationNotFound on re-revoke, got {err2!r}"
    )
    assert err2.get("Message") == not_found, err2
    assert not _authorized_vpc_ids(route53, zone_id, ctx.region), (
        "vpc2 must not appear as authorized after a rejected re-revoke of an already-revoked "
        "authorization"
    )


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(
        f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _authorized_vpc_ids(route53, zone_id: str, region: str) -> set[str]:
    resp = route53.list_vpc_association_authorizations(HostedZoneId=zone_id)
    return {v["VPCId"] for v in resp.get("VPCs", [])}


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
