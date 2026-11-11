"""ipam-resource-cidrs-reflects-manual-modification."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "ipam-resource-cidrs-reflects-manual-modification"
GROUP = "data-plane"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """GetIpamResourceCidrs reflects a ModifyIpamResourceCidr Monitored change (unmanaged <-> ignored)
    in both directions for a discovered VPC outside every IPAM pool; ManagementState follows IPAM's
    background scan, so each read is a bounded poll."""
    ec2 = ctx.client("ec2")

    name = ctx.unique_name("sim2real-ipam-")
    ipam = ec2.create_ipam(
        Description=name,
        OperatingRegions=[{"RegionName": ctx.region}],
        TagSpecifications=[
            {"ResourceType": "ipam", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["Ipam"]
    ipam_id = ipam["IpamId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True))
    ipam = _poll_until(
        lambda: ec2.describe_ipams(IpamIds=[ipam_id])["Ipams"][0],
        lambda i: i["State"] == "create-complete",
        timeout_s=60,
    )
    private_scope_id = ipam["PrivateDefaultScopeId"]

    cidr = "10.202.0.0/16"
    vpc_id = ec2.create_vpc(
        CidrBlock=cidr,
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    def _find_resource_cidr():
        entries = ec2.get_ipam_resource_cidrs(
            IpamScopeId=private_scope_id, ResourceId=vpc_id
        )["IpamResourceCidrs"]
        return entries[0] if entries else None

    resource_cidr = None
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        resource_cidr = _find_resource_cidr()
        if resource_cidr is not None:
            break
        time.sleep(2)

    if resource_cidr is None:
        raise AssertionError(
            f"IPAM did not discover VPC {vpc_id} in the private scope within 15 minutes; "
            "discovery scan latency is undocumented and can exceed this window"
        )
    assert resource_cidr["ManagementState"] == "unmanaged", (
        f"expected freshly-discovered VPC {vpc_id} to start ManagementState=unmanaged, "
        f"got {resource_cidr['ManagementState']!r}"
    )

    ec2.modify_ipam_resource_cidr(
        ResourceId=vpc_id,
        ResourceCidr=cidr,
        ResourceRegion=ctx.region,
        CurrentIpamScopeId=private_scope_id,
        Monitored=False,
    )
    after_ignore = _poll_until(
        _find_resource_cidr,
        lambda c: c is None or c["ManagementState"] == "ignored",
        timeout_s=600,
        interval_s=10,
    )
    assert after_ignore is not None, (
        f"VPC {vpc_id} vanished from GetIpamResourceCidrs after Monitored=False"
    )
    assert after_ignore["ManagementState"] == "ignored", (
        f"expected ManagementState=ignored after Monitored=False, got "
        f"{after_ignore['ManagementState']!r}"
    )

    ec2.modify_ipam_resource_cidr(
        ResourceId=vpc_id,
        ResourceCidr=cidr,
        ResourceRegion=ctx.region,
        CurrentIpamScopeId=private_scope_id,
        Monitored=True,
    )
    after_restore = _poll_until(
        _find_resource_cidr,
        lambda c: c is None or c["ManagementState"] == "unmanaged",
        timeout_s=600,
        interval_s=10,
    )
    assert after_restore is not None, (
        f"VPC {vpc_id} vanished from GetIpamResourceCidrs after Monitored=True"
    )
    assert after_restore["ManagementState"] == "unmanaged", (
        f"expected ManagementState=unmanaged after restoring Monitored=True, got "
        f"{after_restore['ManagementState']!r}"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
