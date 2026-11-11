"""ipam-discovered-resource-cidrs-reflects-scan-results."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "ipam-discovered-resource-cidrs-reflects-scan-results"
GROUP = "data-plane"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """GetIpamDiscoveredResourceCidrs eventually reports the CIDR of a VPC we
    actually created in the IPAM's operating Region -- not a canned/empty
    result -- via the IPAM's default resource discovery."""
    ec2 = ctx.client("ec2")

    ipam_name = ctx.unique_name("sim2real-ipam-")
    ipam = _create_ipam_retrying_slot(
        ctx,
        ec2,
        Description=ipam_name,
        OperatingRegions=[{"RegionName": ctx.region}],
        TagSpecifications=[{"ResourceType": "ipam", "Tags": [{"Key": "Name", "Value": ipam_name}]}],
    )["Ipam"]
    ipam_id = ipam["IpamId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True))
    ipam = _poll_until(
        lambda: ec2.describe_ipams(IpamIds=[ipam_id])["Ipams"][0],
        lambda i: i["State"] == "create-complete",
        timeout_s=60,
    )
    discovery_id = ipam["DefaultResourceDiscoveryId"]

    cidr = "10.201.0.0/16"
    vpc_name = ctx.unique_name("sim2real-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock=cidr,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": vpc_name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    def _find_discovered_vpc():
        entries = ec2.get_ipam_discovered_resource_cidrs(
            IpamResourceDiscoveryId=discovery_id,
            ResourceRegion=ctx.region,
            Filters=[{"Name": "resource-id", "Values": [vpc_id]}],
        )["IpamDiscoveredResourceCidrs"]
        return entries[0] if entries else None

    # IPAM resource-discovery scan latency is not documented as an SLA; poll generously. A
    # still-empty result after the window is a hard failure because it means the scan never surfaced
    # a VPC we know exists.
    discovered = None
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        discovered = _find_discovered_vpc()
        if discovered is not None:
            break
        time.sleep(2)

    if discovered is None:
        raise AssertionError(
            f"IPAM default resource discovery did not surface VPC {vpc_id} within 10 "
            "minutes; discovery scan latency is undocumented and can exceed this window"
        )

    assert discovered["ResourceType"] == "vpc", (
        f"expected ResourceType 'vpc', got {discovered['ResourceType']!r}"
    )
    assert discovered["ResourceCidr"] == cidr, (
        f"expected ResourceCidr {cidr!r}, got {discovered['ResourceCidr']!r}"
    )
    assert discovered["VpcId"] == vpc_id, (
        f"expected VpcId {vpc_id!r}, got {discovered['VpcId']!r}"
    )
    assert discovered["ResourceRegion"] == ctx.region, (
        f"expected ResourceRegion {ctx.region!r}, got {discovered['ResourceRegion']!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last value={value!r})")
        time.sleep(interval_s)
        value = probe()
    return value


def _create_ipam_retrying_slot(ctx, ec2, **kwargs) -> dict:
    """CreateIpam, retrying ONLY the per-Region quota refusal (IPAMs per Region is 1 by default)
    while another IPAM finishes deleting, every 2 s to a deadline capped by ctx.time_left()."""
    from botocore.exceptions import ClientError

    left = ctx.time_left()
    cap = 480.0 if left is None else min(480.0, left)
    deadline = time.monotonic() + cap
    while True:
        try:
            return ec2.create_ipam(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceLimitExceeded":
                raise
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"no IPAM slot freed within {cap:.0f} s: "
                    f"{exc.response['Error'].get('Message')!r}"
                ) from exc
            time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
