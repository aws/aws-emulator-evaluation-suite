"""associate-vpc-without-authorization-rejected."""
from __future__ import annotations

import itertools
import random
import time
import uuid
from typing import Any

from behavioral_harness import tags

CHECK = "associate-vpc-without-authorization-rejected"
GROUP = "error-semantics"
SERVICES = ["route53"]

_octet_counter = itertools.count(random.randint(20, 200))


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateVPCWithHostedZone rejects a well-formed VPC id the account neither owns nor holds an
    authorization for with NotAuthorizedException and no effect, while an owned VPC associates."""
    route53 = ctx.client("route53")
    vpc_owned = _create_vpc(ctx)
    zone_id = _create_private_zone(ctx, vpc_owned)

    # Well-formed VPC id this account never created and holds no authorization for.
    foreign_vpc_id = f"vpc-{uuid.uuid4().hex[:17]}"

    code, message = _error_code(
        lambda: route53.associate_vpc_with_hosted_zone(
            HostedZoneId=zone_id, VPC={"VPCRegion": ctx.region, "VPCId": foreign_vpc_id}
        )
    )
    assert code == "NotAuthorizedException", f"expected NotAuthorizedException, got {code!r}"
    # The denial names the calling principal, so the expected text is built from the caller's
    # own identity.
    caller = ctx.client("sts").get_caller_identity()
    expected = (
        f"User: {caller['Arn']} is not authorized to perform: route53:AssociateVPCWithHostedZone "
        f"on resource: arn:aws:ec2:{ctx.region}:{caller['Account']}:vpc/{foreign_vpc_id}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the zone's VPC list is unchanged (still only the original owned VPC).
    zone_vpcs = {v["VPCId"] for v in route53.get_hosted_zone(Id=zone_id)["VPCs"]}
    assert foreign_vpc_id not in zone_vpcs, f"rejected VPC leaked into zone VPCs: {zone_vpcs}"
    assert zone_vpcs == {vpc_owned}, f"zone VPCs unexpectedly changed: {zone_vpcs}"

    # Positive control in the same file: a real, owned VPC associates cleanly.
    vpc_control = _create_vpc(ctx)
    resp = route53.associate_vpc_with_hosted_zone(
        HostedZoneId=zone_id, VPC={"VPCRegion": ctx.region, "VPCId": vpc_control}
    )
    _wait_change_insync(ctx, resp["ChangeInfo"]["Id"])
    zone_vpcs_after = {v["VPCId"] for v in route53.get_hosted_zone(Id=zone_id)["VPCs"]}
    assert zone_vpcs_after == {vpc_owned, vpc_control}, (
        f"positive-control association did not take effect: {zone_vpcs_after}"
    )


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


def _error_code(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, so accepting a
    call AWS rejects is not reported as a mere error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected NotAuthorizedException but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
