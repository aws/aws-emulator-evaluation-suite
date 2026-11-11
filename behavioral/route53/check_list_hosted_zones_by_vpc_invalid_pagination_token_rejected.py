"""list-hosted-zones-by-vpc-invalid-pagination-token-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-hosted-zones-by-vpc-invalid-pagination-token-rejected"
GROUP = "error-semantics"
SERVICES = ["route53"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListHostedZonesByVPC with a corrupted NextToken returns InvalidPaginationToken,
    not an empty/successful page, and does not disturb the real association state."""
    route53 = ctx.client("route53")
    ec2 = ctx.client("ec2")

    vpc_id, created_vpc = _get_or_create_test_vpc(ec2, ctx)
    if created_vpc:
        ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    zone_name = f"{ctx.unique_name('sim2real-vpctoken-')}.test"
    created = route53.create_hosted_zone(
        Name=zone_name,
        CallerReference=str(uuid.uuid4()),
        HostedZoneConfig={"PrivateZone": True},
        VPC={"VPCId": vpc_id, "VPCRegion": ctx.region},
    )
    zone_id = created["HostedZone"]["Id"]
    ctx.on_cleanup(lambda: route53.delete_hosted_zone(Id=zone_id))
    _wait_for_change_insync(route53, created["ChangeInfo"]["Id"])

    # Positive control: the zone must be visible via a normal (un-tokened) call
    # before we corrupt anything.
    assert _zone_visible_via_vpc(route53, vpc_id, ctx.region, zone_id), (
        f"zone {zone_id} not visible via ListHostedZonesByVPC for {vpc_id} before the "
        "bad-token call; cannot exercise the negative"
    )

    code, message = _client_error(
        lambda: route53.list_hosted_zones_by_vpc(
            VPCId=vpc_id, VPCRegion=ctx.region, NextToken="corrupted-not-a-real-token-xyz"
        )
    )
    assert code == "InvalidPaginationToken", f"expected InvalidPaginationToken, got {code}"
    expected_message = "The nextToken provided is invalid."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The bad-token call must not have disturbed the real association: a normal
    # call still surfaces the zone (positive control re-checked after the error).
    assert _zone_visible_via_vpc(route53, vpc_id, ctx.region, zone_id), (
        f"zone {zone_id} no longer visible via ListHostedZonesByVPC for {vpc_id} after the "
        "bad-token call; the corrupted NextToken disturbed the real association state"
    )


def _client_error(fn):
    """Call fn(); return the ClientError's (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected ListHostedZonesByVPC with a corrupted NextToken to be rejected, but it "
        f"SUCCEEDED and returned {result!r}"
    )


def _get_or_create_test_vpc(ec2, ctx) -> tuple[str, bool]:
    """Return (vpc_id, created) -- reusing the run's shared network when one exists
    (no quota cost, and nothing for this check to delete afterwards) and only creating
    a dedicated VPC when there isn't one. VPC quota is a real, non-code account limit
    that can be exhausted by orphaned VPCs left behind by earlier interrupted test
    runs, so the create path does a best-effort reclaim of this check family's own
    leftover VPCs and retries once before giving up."""
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if default_vpcs:
        return default_vpcs[0]["VpcId"], False

    tag_name = ctx.unique_name("sim2real-vpctoken-vpc-")

    def _do_create():
        return ec2.create_vpc(
            CidrBlock="10.231.0.0/16",
            TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": tag_name}]}],
        )["Vpc"]["VpcId"]

    try:
        vpc_id = _do_create()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "VpcLimitExceeded":
            raise
        _reclaim_orphaned_test_vpcs(ec2)
        vpc_id = _do_create()
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    return vpc_id, True


def _reclaim_orphaned_test_vpcs(ec2) -> None:
    """Best-effort cleanup of orphaned VPCs (identified by this check family's own
    "sim2real-vpctoken-vpc-" tag naming convention) left behind by earlier interrupted
    runs, freeing up room under the account's VPC quota. Route53 VPC associations do
    not block EC2 VpcDelete, so no route53-side teardown is needed here."""
    try:
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "tag:Name", "Values": ["sim2real-vpctoken-vpc-*"]}])["Vpcs"]
    except ClientError:
        return

    for vpc in vpcs:
        try:
            ec2.delete_vpc(VpcId=vpc["VpcId"])
        except ClientError:
            # Still has dependencies we didn't account for -- leave it alone and let
            # a later cleanup pass handle it.
            pass


def _wait_for_change_insync(route53, change_id, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = route53.get_change(Id=change_id)["ChangeInfo"]["Status"]
        if status == "INSYNC":
            return
        time.sleep(interval_s)
    raise AssertionError(f"change {change_id} never reached INSYNC within {timeout_s}s")


def _zone_visible_via_vpc(route53, vpc_id, vpc_region, zone_id, timeout_s=90.0, interval_s=5.0):
    bare_id = zone_id.rsplit("/", 1)[-1]
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = route53.list_hosted_zones_by_vpc(VPCId=vpc_id, VPCRegion=vpc_region)
        if any(s["HostedZoneId"].rsplit("/", 1)[-1] == bare_id for s in resp.get("HostedZoneSummaries", [])):
            return True
        time.sleep(interval_s)
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
