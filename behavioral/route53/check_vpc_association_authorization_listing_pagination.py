"""vpc-association-authorization-listing-pagination."""
from __future__ import annotations

import itertools
import random
import time
import uuid
from typing import Any

from behavioral_harness import tags

CHECK = "vpc-association-authorization-listing-pagination"
GROUP = "ordering"
SERVICES = ["route53"]

_octet_counter = itertools.count(random.randint(20, 200))
_NUM_AUTHORIZATIONS = 5


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListVPCAssociationAuthorizations with MaxResults=2 returns every authorized VPC exactly once
    across multiple pages, walking the NextToken chain to the end."""
    route53 = ctx.client("route53")
    zone_vpc = _create_vpc(ctx)
    zone_id = _create_private_zone(ctx, zone_vpc)

    # Route 53 does not verify that an authorized VPC (normally another account's) exists, so
    # well-formed synthetic ids suffice and spare the VPC quota.
    auth_vpcs = [f"vpc-{uuid.uuid4().hex[:17]}" for _ in range(_NUM_AUTHORIZATIONS)]
    for vpc_id in auth_vpcs:
        route53.create_vpc_association_authorization(
            HostedZoneId=zone_id, VPC={"VPCRegion": ctx.region, "VPCId": vpc_id}
        )
        ctx.on_cleanup(
            lambda v=vpc_id: route53.delete_vpc_association_authorization(
                HostedZoneId=zone_id, VPC={"VPCRegion": ctx.region, "VPCId": v}
            )
        )

    collected: list[str] = []
    seen: set[str] = set()
    token = None
    pages = 0
    while True:
        kwargs: dict[str, Any] = {"HostedZoneId": zone_id, "MaxResults": "2"}
        if token:
            kwargs["NextToken"] = token
        resp = route53.list_vpc_association_authorizations(**kwargs)
        pages += 1
        for vpc in resp.get("VPCs", []):
            vpc_id = vpc["VPCId"]
            assert vpc_id not in seen, f"duplicate VPCId {vpc_id} across pagination pages"
            seen.add(vpc_id)
            collected.append(vpc_id)
        token = resp.get("NextToken")
        if not token:
            break
        assert pages <= _NUM_AUTHORIZATIONS + 2, "pagination did not terminate as expected"

    assert pages >= 2, f"expected pagination to span multiple pages with MaxResults=2, got {pages}"
    assert set(collected) == set(auth_vpcs), (
        f"pagination walk missed/added entries: expected {set(auth_vpcs)}, got {set(collected)}"
    )
    assert len(collected) == _NUM_AUTHORIZATIONS, f"expected {_NUM_AUTHORIZATIONS} entries, got {len(collected)}"


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


def _wait_change_insync(ctx: Any, change_id: str, timeout_s: float = 150.0, interval_s: float = 3.0) -> None:
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
