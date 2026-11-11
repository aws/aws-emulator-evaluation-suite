"""delete-vpc-association-authorization-revokes-future-association."""
from __future__ import annotations

import itertools
import random
import time
from typing import Any

from behavioral_harness import tags

CHECK = "delete-vpc-association-authorization-revokes-future-association"
GROUP = "state-machine"
SERVICES = ["route53"]

_octet_counter = itertools.count(random.randint(20, 200))


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteVPCAssociationAuthorization removes the entry from the listing, and deleting the same
    VPC/zone pair again is rejected with VPCAssociationAuthorizationNotFound; a sibling deletes cleanly.

    Reference: https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/hosted-zone-private-associate-vpcs-different-accounts.html
    """
    # The authorization only gates a cross-account associate; with one credential set a
    # same-account associate succeeds regardless, so only the ledger contract is observable here.
    route53 = ctx.client("route53")
    zone_vpc = _create_vpc(ctx)
    zone_id = _create_private_zone(ctx, zone_vpc)

    vpc_b = _create_vpc(ctx)  # will be revoked twice (the negative path)
    vpc_c = _create_vpc(ctx)  # positive control: authorize + delete once, cleanly

    route53.create_vpc_association_authorization(
        HostedZoneId=zone_id, VPC={"VPCRegion": ctx.region, "VPCId": vpc_b}
    )
    route53.create_vpc_association_authorization(
        HostedZoneId=zone_id, VPC={"VPCRegion": ctx.region, "VPCId": vpc_c}
    )

    listed = _authorized_vpc_ids(ctx, zone_id)
    assert vpc_b in listed and vpc_c in listed, f"authorizations missing from ledger: {listed}"

    route53.delete_vpc_association_authorization(
        HostedZoneId=zone_id, VPC={"VPCRegion": ctx.region, "VPCId": vpc_c}
    )
    listed_after_c = _authorized_vpc_ids(ctx, zone_id)
    assert vpc_c not in listed_after_c, f"positive-control delete did not take effect: {listed_after_c}"
    assert vpc_b in listed_after_c, "unrelated authorization (vpc_b) was disturbed by vpc_c's delete"

    route53.delete_vpc_association_authorization(
        HostedZoneId=zone_id, VPC={"VPCRegion": ctx.region, "VPCId": vpc_b}
    )
    listed_after_b = _authorized_vpc_ids(ctx, zone_id)
    assert vpc_b not in listed_after_b, f"vpc_b authorization still listed after revoke: {listed_after_b}"

    # Break exactly one thing: revoke the ALREADY-revoked vpc_b/zone pair again.
    code, message = _error(
        lambda: route53.delete_vpc_association_authorization(
            HostedZoneId=zone_id, VPC={"VPCRegion": ctx.region, "VPCId": vpc_b}
        )
    )
    assert code == "VPCAssociationAuthorizationNotFound", (
        f"expected VPCAssociationAuthorizationNotFound, got {code!r}"
    )
    expected_message = (
        f"No authorization exists for hosted zone: {zone_id} and vpc: {vpc_b}, {ctx.region}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The rejected re-delete must not undo the earlier revoke.
    final_listed = _authorized_vpc_ids(ctx, zone_id)
    assert vpc_b not in final_listed, f"rejected re-delete left vpc_b in the ledger: {final_listed}"


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
    # No INSYNC wait: that tracks DNS propagation (often over a minute), which the
    # authorization ledger does not depend on.
    return zone_id


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). A successful call raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
