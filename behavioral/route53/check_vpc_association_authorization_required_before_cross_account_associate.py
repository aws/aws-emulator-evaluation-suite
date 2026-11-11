"""vpc-association-authorization-required-before-cross-account-associate."""
from __future__ import annotations

import itertools
import random
import time
from typing import Any

from behavioral_harness import tags

CHECK = "vpc-association-authorization-required-before-cross-account-associate"
GROUP = "ordering"
SERVICES = ["route53"]

_octet_counter = itertools.count(random.randint(20, 200))


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Deleting a never-created VPC association authorization fails with
    VPCAssociationAuthorizationNotFound; after Create and an Associate it succeeds, and a re-delete
    fails again. The cross-account Associate gate needs two accounts, so it is not exercised here.

    Reference: https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/hosted-zone-private-associate-vpcs-different-accounts.html
    """
    route53 = ctx.client("route53")
    zone_vpc = _create_vpc(ctx)
    zone_id = _create_private_zone(ctx, zone_vpc)
    vpc_target = _create_vpc(ctx)

    # Order violation: revoke an authorization that was NEVER created for this VPC/zone pair.
    not_found = (
        f"No authorization exists for hosted zone: {zone_id} and vpc: {vpc_target}, {ctx.region}"
    )
    err = _client_error(
        lambda: route53.delete_vpc_association_authorization(
            HostedZoneId=zone_id, VPC={"VPCRegion": ctx.region, "VPCId": vpc_target}
        )
    )
    assert err.get("Code") == "VPCAssociationAuthorizationNotFound", (
        f"expected VPCAssociationAuthorizationNotFound, got {err!r}"
    )
    assert err.get("Message") == not_found, err

    # Effect absent: still nothing in the ledger for this zone.
    assert vpc_target not in _authorized_vpc_ids(ctx, zone_id), "phantom authorization appeared"

    route53.create_vpc_association_authorization(
        HostedZoneId=zone_id, VPC={"VPCRegion": ctx.region, "VPCId": vpc_target}
    )
    assert vpc_target in _authorized_vpc_ids(ctx, zone_id), "authorization not visible after create"

    resp = route53.associate_vpc_with_hosted_zone(
        HostedZoneId=zone_id, VPC={"VPCRegion": ctx.region, "VPCId": vpc_target}
    )
    _wait_change_insync(ctx, resp["ChangeInfo"]["Id"])
    zone_vpcs = {v["VPCId"] for v in route53.get_hosted_zone(Id=zone_id)["VPCs"]}
    assert vpc_target in zone_vpcs, f"association did not take effect: {zone_vpcs}"

    route53.delete_vpc_association_authorization(
        HostedZoneId=zone_id, VPC={"VPCRegion": ctx.region, "VPCId": vpc_target}
    )
    assert vpc_target not in _authorized_vpc_ids(ctx, zone_id), "authorization still listed after delete"

    err2 = _client_error(
        lambda: route53.delete_vpc_association_authorization(
            HostedZoneId=zone_id, VPC={"VPCRegion": ctx.region, "VPCId": vpc_target}
        )
    )
    assert err2.get("Code") == "VPCAssociationAuthorizationNotFound", (
        f"expected VPCAssociationAuthorizationNotFound on re-delete, got {err2!r}"
    )
    assert err2.get("Message") == not_found, err2
    assert vpc_target not in _authorized_vpc_ids(ctx, zone_id), "phantom authorization reappeared"


def _authorized_vpc_ids(ctx: Any, zone_id: str) -> set[str]:
    route53 = ctx.client("route53")
    resp = route53.list_vpc_association_authorizations(HostedZoneId=zone_id)
    return {v["VPCId"] for v in resp.get("VPCs", [])}


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


def _wait_change_insync(ctx: Any, change_id: str, timeout_s: float = 240.0, interval_s: float = 3.0) -> None:
    route53 = ctx.client("route53")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = route53.get_change(Id=change_id)["ChangeInfo"]["Status"]
        if status == "INSYNC":
            return
        time.sleep(interval_s)
    raise AssertionError(f"change {change_id} never reached INSYNC within {timeout_s}s (last {status})")


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
